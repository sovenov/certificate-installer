#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Пакетная установка сертификатов, CRL, PKCS#7, SST и PFX рядом со скриптом, Windows 10/11.

Запуск: python install_certificates.py
Проверка без установки: python install_certificates.py --dry-run
Требуется Python 3.8+; сторонние библиотеки не нужны.

Два выбора в консоли применяются ко всем файлам:
  1. Текущий пользователь либо локальный компьютер (нужны права администратора).
  2. Автоматическое распределение либо всё в Root.

Правила автоматического режима:
  CA с собственной подписью -> Root (доверенные корневые центры сертификации);
  остальные CA              -> CA (промежуточные центры сертификации);
  конечные сертификаты     -> My (личное);
  списки отзыва CRL        -> CA.
CA определяется по Basic Constraints (новому или старому расширению).
Сертификат без этого расширения считается конечным: старый корневой
сертификат без Basic Constraints можно установить явным выбором Root.
Это явная политика скрипта, а не вызов автоматического мастера Windows.

Поддерживаются .crt/.cer/.pem/.der, .crl, .p7b/.p7c, .sst и .pfx/.p12.
PEM-пакет обрабатывается целиком: сертификаты, CRL и PKCS#7; ошибки
отдельных блоков сообщаются, остальные блоки продолжают обрабатываться.
SST — сериализованное хранилище Windows. Подкаталоги не просматриваются.
Для PFX/P12 пароль запрашивается скрыто; неверный пароль можно повторить,
Ctrl+C/EOF отменяет только этот файл. Пароли не передаются в командной
строке и не записываются в журнал. Импортируемые ключи сохраняются для
выбранного пользователя/компьютера, не помечаются экспортируемыми,
существующие контейнеры ключей не перезаписываются. Проверка --dry-run
импортирует ключи только в память (PKCS12_NO_PERSIST_KEY) и не открывает
целевые хранилища. Отдельные PEM-файлы закрытых ключей не поддерживаются.
Итог считает отдельные объекты; отменённые PFX считаются отдельно по файлам.
Одинаковые публичные сертификаты пропускаются; для сертификата PFX
обновляется привязка закрытого ключа. CRL заменяется только более свежим.
В Root следует устанавливать только те сертификаты, которым вы доверяете.
Установка в хранилище сама по себе не проверяет доверие к цепочке и срок действия.

Используемые API:
https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptqueryobject
https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-certaddcrlcontexttostore
https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-pfximportcertstore
"""

import argparse
import base64
import binascii
import getpass
import re
import warnings
import ctypes as ct
from ctypes import wintypes as wt
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import os
import sys


CERT_QUERY_OBJECT_FILE = 1
CERT_QUERY_OBJECT_BLOB = 2
CERT_QUERY_CONTENT_SERIALIZED_STORE = 4
CERT_QUERY_CONTENT_CERT = 1
CERT_QUERY_CONTENT_CRL = 3
CERT_QUERY_CONTENT_PKCS7_SIGNED = 8
CERT_QUERY_CONTENT_FLAGS = (1 << CERT_QUERY_CONTENT_CERT) | (1 << CERT_QUERY_CONTENT_CRL)
CERT_QUERY_FORMAT_FLAGS = (1 << 1) | (1 << 2)  # Binary DER, Base64 (including PEM)
CERT_STORE_PROV_SYSTEM_W = 10
CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
CERT_STORE_ADD_NEW = 1
CERT_STORE_ADD_USE_EXISTING = 2
CERT_KEY_PROV_INFO_PROP_ID = 2
CRYPT_USER_KEYSET = 0x00001000
CRYPT_MACHINE_KEYSET = 0x00000020
PKCS12_NO_PERSIST_KEY = 0x00008000
PKCS12_INCLUDE_EXTENDED_PROPERTIES = 0x00000010
CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES = 7
CRYPT_E_EXISTS = 0x80092005
CRYPT_E_NOT_FOUND = 0x80092004
ERROR_NO_MORE_FILES = 18
NTE_BAD_SIGNATURE = 0x80090006
STATUS_INVALID_SIGNATURE = 0xC000A000
X509_ASN_ENCODING = 1

SUPPORTED_SUFFIXES = {".crt", ".cer", ".crl", ".pem", ".der", ".p7b", ".p7c", ".sst", ".pfx", ".p12"}
PEM_CONTENT_FLAGS = {
    b"CERTIFICATE": 1 << CERT_QUERY_CONTENT_CERT,
    b"X509 CERTIFICATE": 1 << CERT_QUERY_CONTENT_CERT,
    b"X509 CRL": 1 << CERT_QUERY_CONTENT_CRL,
    b"CRL": 1 << CERT_QUERY_CONTENT_CRL,
    b"PKCS7": 1 << CERT_QUERY_CONTENT_PKCS7_SIGNED,
    b"CMS": 1 << CERT_QUERY_CONTENT_PKCS7_SIGNED,
}
PEM_BEGIN = re.compile(br"-----BEGIN ([A-Z0-9][A-Z0-9 -]*)-----")


class FileCancelled(ValueError):
    """Отмена пароля одного файла; обработка остальных файлов продолжается."""


STORE_LABELS = {
    "Root": "Доверенные корневые центры сертификации",
    "CA": "Промежуточные центры сертификации",
    "My": "Личное",
}
LOCATION_LABELS = {"user": "Текущий пользователь", "machine": "Локальный компьютер"}


# Структуры wincrypt.h. ctypes сохраняет штатное выравнивание для x86/x64.
class BLOB(ct.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ct.POINTER(wt.BYTE))]


class BIT_BLOB(ct.Structure):
    _fields_ = BLOB._fields_ + [("cUnusedBits", wt.DWORD)]


class ALGORITHM(ct.Structure):
    _fields_ = [("pszObjId", ct.c_char_p), ("Parameters", BLOB)]


class PUBLIC_KEY_INFO(ct.Structure):
    _fields_ = [("Algorithm", ALGORITHM), ("PublicKey", BIT_BLOB)]


class EXTENSION(ct.Structure):
    _fields_ = [("pszObjId", ct.c_char_p), ("fCritical", wt.BOOL), ("Value", BLOB)]


class CERT_INFO(ct.Structure):
    _fields_ = [
        ("dwVersion", wt.DWORD), ("SerialNumber", BLOB),
        ("SignatureAlgorithm", ALGORITHM), ("Issuer", BLOB),
        ("NotBefore", wt.FILETIME), ("NotAfter", wt.FILETIME),
        ("Subject", BLOB), ("SubjectPublicKeyInfo", PUBLIC_KEY_INFO),
        ("IssuerUniqueId", BIT_BLOB), ("SubjectUniqueId", BIT_BLOB),
        ("cExtension", wt.DWORD), ("rgExtension", ct.POINTER(EXTENSION)),
    ]


class CERT_CONTEXT(ct.Structure):
    _fields_ = [
        ("dwCertEncodingType", wt.DWORD), ("pbCertEncoded", ct.POINTER(wt.BYTE)),
        ("cbCertEncoded", wt.DWORD), ("pCertInfo", ct.POINTER(CERT_INFO)),
        ("hCertStore", wt.HANDLE),
    ]


class BASIC_CONSTRAINTS2(ct.Structure):
    _fields_ = [("fCA", wt.BOOL), ("fPathLenConstraint", wt.BOOL),
                ("dwPathLenConstraint", wt.DWORD)]


class BASIC_CONSTRAINTS(ct.Structure):
    _fields_ = [
        ("SubjectType", BIT_BLOB), ("fPathLenConstraint", wt.BOOL),
        ("dwPathLenConstraint", wt.DWORD), ("cSubtreesConstraint", wt.DWORD),
        ("rgSubtreesConstraint", ct.POINTER(BLOB)),
    ]


class CryptoAPI:
    """Чтение объектов и работа с явно выбранной областью хранилищ Windows."""

    def __init__(self, pfx_importer=None):
        self.dll = ct.WinDLL("crypt32.dll", use_last_error=True)
        pointer = ct.c_void_p
        dword_ptr = ct.POINTER(wt.DWORD)
        self._bind("CryptQueryObject", wt.BOOL, [
            wt.DWORD, pointer, wt.DWORD, wt.DWORD, wt.DWORD,
            dword_ptr, dword_ptr, dword_ptr, pointer, pointer, ct.POINTER(pointer),
        ])
        self._bind("CertFreeCertificateContext", wt.BOOL, [pointer])
        self._bind("CertFreeCRLContext", wt.BOOL, [pointer])
        self._bind("CertEnumCertificatesInStore", pointer, [wt.HANDLE, pointer])
        self._bind("CertEnumCRLsInStore", pointer, [wt.HANDLE, pointer])
        self._bind("CryptDecodeObjectEx", wt.BOOL, [
            wt.DWORD, ct.c_char_p, pointer, wt.DWORD, wt.DWORD,
            pointer, pointer, dword_ptr,
        ])
        self._bind("CertCompareCertificateName", wt.BOOL,
                   [wt.DWORD, ct.POINTER(BLOB), ct.POINTER(BLOB)])
        self._bind("CryptVerifyCertificateSignatureEx", wt.BOOL, [
            pointer, wt.DWORD, wt.DWORD, pointer, wt.DWORD, pointer, wt.DWORD, pointer,
        ])
        self._bind("CertOpenStore", wt.HANDLE,
                   [pointer, wt.DWORD, pointer, wt.DWORD, pointer])
        self._bind("CertCloseStore", wt.BOOL, [wt.HANDLE, wt.DWORD])
        self._bind("PFXIsPFXBlob", wt.BOOL, [ct.POINTER(BLOB)])
        self._bind("PFXVerifyPassword", wt.BOOL, [ct.POINTER(BLOB), wt.LPCWSTR, wt.DWORD])
        self._bind("PFXImportCertStore", wt.HANDLE, [ct.POINTER(BLOB), wt.LPCWSTR, wt.DWORD])
        self._bind("CertGetCertificateContextProperty", wt.BOOL,
                   [pointer, wt.DWORD, pointer, dword_ptr])
        # Injectable seam lets tests force NO_PERSIST even for installation paths.
        self.pfx_importer = pfx_importer or self._native_pfx_import
        for name in ("CertAddCertificateContextToStore", "CertAddCRLContextToStore"):
            self._bind(name, wt.BOOL, [wt.HANDLE, pointer, wt.DWORD, pointer])

    def _bind(self, name, result, arguments):
        function = getattr(self.dll, name)
        function.restype = result
        function.argtypes = arguments

    @staticmethod
    def _error(operation):
        # ctypes может вернуть HRESULT/NTSTATUS как знаковое 32-битное число.
        code = ct.get_last_error() & 0xFFFFFFFF
        message = ct.FormatError(ct.c_long(code).value).strip()
        return OSError(code, "{}: {} (0x{:08X})".format(operation, message, code))

    @contextmanager
    def load(self, path):
        """Определяет реальный тип содержимого независимо от расширения."""
        kind = wt.DWORD()
        context = ct.c_void_p()
        filename = ct.c_wchar_p(str(path))
        if not self.dll.CryptQueryObject(
            CERT_QUERY_OBJECT_FILE, filename, CERT_QUERY_CONTENT_FLAGS,
            CERT_QUERY_FORMAT_FLAGS, 0, None, ct.byref(kind), None,
            None, None, ct.byref(context),
        ):
            raise self._error("Не удалось прочитать сертификат/CRL")
        try:
            yield kind.value, context
        finally:
            free = (self.dll.CertFreeCertificateContext
                    if kind.value == CERT_QUERY_CONTENT_CERT else self.dll.CertFreeCRLContext)
            free(context)

    def _store_objects(self, handle):
        """Перебор освобождает предыдущий контекст; close() освобождает текущий."""
        for kind, enumerate_next, free in (
            (CERT_QUERY_CONTENT_CERT, self.dll.CertEnumCertificatesInStore,
             self.dll.CertFreeCertificateContext),
            (CERT_QUERY_CONTENT_CRL, self.dll.CertEnumCRLsInStore,
             self.dll.CertFreeCRLContext),
        ):
            context = None
            try:
                while True:
                    context = enumerate_next(handle, context)
                    if not context:
                        if (ct.get_last_error() & 0xFFFFFFFF) not in {
                            CRYPT_E_NOT_FOUND, ERROR_NO_MORE_FILES,
                        }:
                            raise self._error("Не удалось перечислить содержимое файла")
                        break
                    yield kind, context
            finally:
                if context:
                    free(context)

    @staticmethod
    @contextmanager
    def _password_buffer(password):
        if password is None:
            yield None
            return
        buffer = ct.create_unicode_buffer(password)
        try:
            yield ct.cast(buffer, wt.LPCWSTR)
        finally:
            ct.memset(ct.addressof(buffer), 0, ct.sizeof(buffer))

    def _native_pfx_import(self, blob, password, flags):
        with self._password_buffer(password) as value:
            return self.dll.PFXImportCertStore(ct.byref(blob), value, flags)

    def _verify_pfx_password(self, blob, password):
        with self._password_buffer(password) as value:
            return bool(self.dll.PFXVerifyPassword(ct.byref(blob), value, 0))

    def _open_pfx(self, blob, path, location, dry_run, password_prompt):
        password = None
        for candidate in ("", None):
            if self._verify_pfx_password(blob, candidate):
                password = candidate
                break
        else:
            prompt = password_prompt or prompt_pfx_password
            attempt = 0
            while True:
                attempt += 1
                try:
                    password = prompt(path, attempt)
                except (KeyboardInterrupt, EOFError):
                    raise FileCancelled("Ввод пароля отменён; файл пропущен") from None
                if password is None:
                    raise FileCancelled("Ввод пароля отменён; файл пропущен")
                if not isinstance(password, str) or "\0" in password:
                    print("Пароль должен быть строкой без нулевых символов.")
                    password = None
                    continue
                if self._verify_pfx_password(blob, password):
                    break
                password = None
                print("Неверный пароль PFX/P12. Повторите ввод или нажмите Ctrl+C для отмены файла.")
        flags = ((CRYPT_USER_KEYSET if location == "user" else CRYPT_MACHINE_KEYSET) |
                 PKCS12_INCLUDE_EXTENDED_PROPERTIES)
        if dry_run:
            flags |= PKCS12_NO_PERSIST_KEY
        try:
            handle = self.pfx_importer(blob, password, flags)
        finally:
            password = None
        if not handle:
            raise self._error("Не удалось импортировать PFX/P12")
        return handle

    @contextmanager
    def _data_objects(self, data, path, location, dry_run, password_prompt, content_flags=None):
        buffer = (wt.BYTE * len(data)).from_buffer_copy(data)
        blob = BLOB(len(data), ct.cast(buffer, ct.POINTER(wt.BYTE)))
        if content_flags is None and self.dll.PFXIsPFXBlob(ct.byref(blob)):
            handle = self._open_pfx(blob, path, location, dry_run, password_prompt)
        else:
            opened = wt.HANDLE()
            flags = ((CERT_QUERY_CONTENT_FLAGS | (1 << CERT_QUERY_CONTENT_PKCS7_SIGNED) |
                      (1 << CERT_QUERY_CONTENT_SERIALIZED_STORE))
                     if content_flags is None else content_flags)
            if not self.dll.CryptQueryObject(
                CERT_QUERY_OBJECT_BLOB, ct.byref(blob), flags,
                CERT_QUERY_FORMAT_FLAGS, 0, None, None, None,
                ct.byref(opened), None, None,
            ):
                raise self._error("Не удалось прочитать сертификат/CRL/PKCS#7/SST")
            handle = opened.value
        if not handle:
            raise ValueError("Файл не содержит доступного хранилища сертификатов/CRL")
        objects = self._store_objects(handle)
        try:
            yield objects
        finally:
            objects.close()
            self.dll.CertCloseStore(handle, 0)

    def _pem_objects(self, data, path, location, dry_run, password_prompt):
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
        markers = list(PEM_BEGIN.finditer(data))
        if not markers:
            yield None, ValueError("Некорректные границы PEM")
            return
        position = 0
        for index, begin in enumerate(markers):
            gap = data[position:begin.start()]
            if b"-----BEGIN" in gap or b"-----END" in gap:
                yield None, ValueError("Повреждённые границы между PEM-блоками")
            label = begin.group(1)
            next_start = markers[index+1].start() if index+1 < len(markers) else len(data)
            ending = b"-----END " + label + b"-----"
            end = data.find(ending, begin.end(), next_start)
            if end < 0:
                yield None, ValueError("Незавершённый PEM-блок " + label.decode("ascii"))
                position = next_start
                continue
            position = end + len(ending)
            if label not in PEM_CONTENT_FLAGS:
                yield None, ValueError("Неподдерживаемый PEM-блок " + label.decode("ascii"))
                continue
            try:
                encoded = re.sub(br"\s+", b"", data[begin.end():end])
                decoded = base64.b64decode(encoded, validate=True)
                with self._data_objects(decoded, path, location, dry_run, password_prompt,
                                        content_flags=PEM_CONTENT_FLAGS[label]) as objects:
                    count = 0
                    for item in objects:
                        count += 1
                        yield item
                    if not count:
                        raise ValueError("PEM-блок не содержит сертификатов/CRL")
            except FileCancelled:
                raise
            except (OSError, ValueError, binascii.Error) as error:
                yield None, ValueError("Ошибка PEM-блока {}: {}".format(label.decode("ascii"), error))
        trailing = data[position:]
        if b"-----BEGIN" in trailing or b"-----END" in trailing:
            yield None, ValueError("Повреждённые границы после PEM-блока")

    @contextmanager
    def load_objects(self, path, location="user", dry_run=False, password_prompt=None):
        """Временные объекты; (None, ValueError) сообщает ошибку одного PEM-блока.

        pfx_importer принимает (BLOB, password-or-None, flags) и передаёт владение
        возвращённым HCERTSTORE этому методу. Для тестов он ОБЯЗАН выставить
        PKCS12_NO_PERSIST_KEY: MEMORY-назначение само по себе не защищает ключи.
        """
        data = Path(path).read_bytes()
        # ASN.1 and serialized stores can contain ASCII PEM markers in values.
        # A PEM candidate must be text, not a binary container with such metadata.
        text = all(byte >= 32 or byte in (9, 10, 13) for byte in data)
        if text and (b"-----BEGIN" in data or b"-----END" in data):
            objects = self._pem_objects(data, path, location, dry_run, password_prompt)
            try:
                yield objects
            finally:
                objects.close()
        else:
            with self._data_objects(data, path, location, dry_run, password_prompt) as objects:
                yield objects

    def _is_ca(self, info):
        # Сначала Basic Constraints v2, затем устаревшее расширение v1.
        for oid, structure in ((b"2.5.29.19", BASIC_CONSTRAINTS2),
                               (b"2.5.29.10", BASIC_CONSTRAINTS)):
            for index in range(info.cExtension):
                extension = info.rgExtension[index]
                if extension.pszObjId != oid:
                    continue
                size = wt.DWORD()
                parameters = (X509_ASN_ENCODING, oid, extension.Value.pbData,
                              extension.Value.cbData, 0, None)
                if not self.dll.CryptDecodeObjectEx(*parameters, None, ct.byref(size)):
                    raise self._error("Не удалось разобрать Basic Constraints")
                buffer = ct.create_string_buffer(size.value)
                if not self.dll.CryptDecodeObjectEx(*parameters, buffer, ct.byref(size)):
                    raise self._error("Не удалось разобрать Basic Constraints")
                value = ct.cast(buffer, ct.POINTER(structure)).contents
                if oid == b"2.5.29.19":
                    return bool(value.fCA)
                return bool(value.SubjectType.cbData and value.SubjectType.pbData[0] & 0x80)
        return False

    def select_store(self, kind, context, mode):
        if mode == "root":
            return "Root"
        if kind == CERT_QUERY_CONTENT_CRL:
            return "CA"
        info = ct.cast(context, ct.POINTER(CERT_CONTEXT)).contents.pCertInfo.contents
        if not self._is_ca(info):
            return "My"
        same_name = self.dll.CertCompareCertificateName(
            X509_ASN_ENCODING, ct.byref(info.Subject), ct.byref(info.Issuer))
        if same_name:
            if self.dll.CryptVerifyCertificateSignatureEx(
                None, X509_ASN_ENCODING, 2, context, 2, context, 0, None,
            ):
                return "Root"
            # Self-issued CA может быть подписан другим ключом (смена ключей).
            # Ошибку провайдера/алгоритма нельзя считать результатом классификации.
            if (ct.get_last_error() & 0xFFFFFFFF) not in {
                NTE_BAD_SIGNATURE, STATUS_INVALID_SIGNATURE,
            }:
                raise self._error("Не удалось проверить собственную подпись CA")
        return "CA"

    @contextmanager
    def open_store(self, name, location):
        flag = (CERT_SYSTEM_STORE_CURRENT_USER if location == "user"
                else CERT_SYSTEM_STORE_LOCAL_MACHINE)
        handle = self.dll.CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W, 0, None, flag, ct.c_wchar_p(name))
        if not handle:
            raise self._error("Не удалось открыть " + name)
        try:
            yield handle
        finally:
            self.dll.CertCloseStore(handle, 0)

    def add(self, handle, kind, context):
        """False означает, что объект или более свежий CRL уже есть."""
        if kind == CERT_QUERY_CONTENT_CERT:
            function = self.dll.CertAddCertificateContextToStore
            # Persisted PFX association must reach an existing public certificate.
            size = wt.DWORD()
            has_key = self.dll.CertGetCertificateContextProperty(
                context, CERT_KEY_PROV_INFO_PROP_ID, None, ct.byref(size))
            if not has_key and (ct.get_last_error() & 0xFFFFFFFF) != CRYPT_E_NOT_FOUND:
                raise self._error("Не удалось прочитать привязку закрытого ключа")
            disposition = CERT_STORE_ADD_USE_EXISTING if has_key else CERT_STORE_ADD_NEW
        else:
            function = self.dll.CertAddCRLContextToStore
            disposition = CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES
        if function(handle, context, disposition, None):
            return True
        if (ct.get_last_error() & 0xFFFFFFFF) == CRYPT_E_EXISTS:
            return False
        raise self._error("Ошибка установки")


def find_files(directory):
    return sorted(
        (path for path in directory.iterdir()
         if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES),
        key=lambda path: (path.name.casefold(), path.name),
    )


def prompt_pfx_password(path, attempt):
    """Скрытый ввод; getpass fallback с отображением символов не допускается."""
    print("PFX/P12: {}. Ctrl+C или EOF — отменить только этот файл.".format(path.name))
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass("Пароль PFX/P12 (попытка {}): ".format(attempt))
        except getpass.GetPassWarning:
            raise FileCancelled("Скрытый ввод пароля недоступен; файл отменён") from None


def ask_choice(title, options):
    print("\n" + title)
    for number, (_, label) in enumerate(options, 1):
        print("  {}. {}".format(number, label))
    while True:
        answer = input("Выберите 1 или 2 (0 — выход): ").strip()
        if answer == "0":
            return None
        if answer in {"1", "2"}:
            return options[int(answer) - 1][0]
        print("Введите 1, 2 или 0.")


def is_admin():
    shell32 = ct.WinDLL("shell32.dll", use_last_error=True)
    shell32.IsUserAnAdmin.argtypes = []
    shell32.IsUserAnAdmin.restype = wt.BOOL
    return bool(shell32.IsUserAnAdmin())


@dataclass
class Results:
    installed: int = 0
    skipped: int = 0
    errors: int = 0
    planned: int = 0
    cancelled: int = 0


def install_files(files, api, location, mode, dry_run=False, password_prompt=None):
    results = Results()
    for path in files:
        try:
            with api.load_objects(path, location=location, dry_run=dry_run,
                                  password_prompt=password_prompt) as objects:
                count = 0
                for count, (kind, context) in enumerate(objects, 1):
                    label = "{} [{} #{}]".format(
                        path.name, "CRL" if kind == CERT_QUERY_CONTENT_CRL else "сертификат", count)
                    try:
                        if kind is None:
                            raise context
                        store = api.select_store(kind, context, mode)
                        target = "{} / {}".format(LOCATION_LABELS[location], STORE_LABELS[store])
                        if dry_run:
                            results.planned += 1
                            print("[ПЛАН] {} -> {}".format(label, target))
                            continue
                        with api.open_store(store, location) as handle:
                            added = api.add(handle, kind, context)
                        if added:
                            results.installed += 1
                            print("[OK] {} -> {}".format(label, target))
                        else:
                            results.skipped += 1
                            print("[ЕСТЬ] {} -> {} (уже есть; для CRL — такой же или новее)".format(
                                label, target))
                    except (OSError, ValueError) as error:
                        results.errors += 1
                        print("[ОШИБКА] {}: {}".format(label, error))
                if not count:
                    raise ValueError("В файле нет сертификатов или CRL")
        except FileCancelled as error:
            results.cancelled += 1
            print("[ОТМЕНА] {}: {}".format(path.name, error))
        except (OSError, ValueError) as error:
            results.errors += 1
            print("[ОШИБКА] {}: {}".format(path.name, error))
    print("\nИтог: объектов установлено {}, уже есть {}, ошибок {}, только проверено {}, отменено файлов {}.".format(
        results.installed, results.skipped, results.errors, results.planned, results.cancelled))
    return results


def main(dry_run=False):
    if os.name != "nt":
        print("Этот скрипт предназначен для Windows 10 и Windows 11.")
        return 1
    directory = Path(__file__).resolve().parent
    print("Пакетная установка сертификатов и списков отзыва")
    print("Папка скрипта: {}".format(directory))
    files = find_files(directory)
    if not files:
        print("Рядом со скриптом нет файлов .crt/.cer/.pem/.der/.crl/.p7b/.p7c/.sst/.pfx/.p12. Подкаталоги не проверяются.")
        return 0
    print("Найдено файлов: {}".format(len(files)))
    location = ask_choice("Расположение хранилища:", list(LOCATION_LABELS.items()))
    if location is None:
        return 0
    mode = ask_choice("Выбор хранилища для ВСЕХ файлов:", [
        ("auto", "Автоматически по типу: корневые CA -> Root, остальные CA/CRL -> CA, конечные -> My"),
        ("root", "Все файлы -> Доверенные корневые центры сертификации (Root)"),
    ])
    if mode is None:
        return 0
    if dry_run:
        print("\nПРОВЕРКА: хранилища не изменяются.")
    elif location == "machine" and not is_admin():
        print("\nДля локального компьютера нужны права администратора.")
        print("Откройте командную строку или Windows Terminal от имени администратора")
        print('и выполните: python "{}"'.format(Path(__file__).resolve()))
        print("Ничего не установлено. Затем повторите оба выбора.")
        return 1
    print("\nОбработка файлов:")
    results = install_files(files, CryptoAPI(), location, mode, dry_run)
    return 1 if results.errors or results.cancelled else 0


def cli():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="проверить файлы без установки")
    parser.add_argument("--no-pause", action="store_true", help="не ждать Enter перед закрытием")
    args = parser.parse_args()
    # Сохраняем читаемый вывод при перенаправлении в файл, включая русские имена.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    try:
        code = main(args.dry_run)
    except (KeyboardInterrupt, EOFError):
        print("\nОперация прервана. Уже установленные объекты остаются в хранилище.")
        code = 130
    except OSError as error:
        print("\nОшибка: {}".format(error))
        code = 1
    if not args.no_pause and sys.stdin.isatty():
        try:
            input("\nНажмите Enter для выхода...")
        except (KeyboardInterrupt, EOFError):
            pass
    return code


if __name__ == "__main__":
    sys.exit(cli())
