"""Stdlib tests. Native integration uses only disposable memory stores.

Run: python -m unittest -v test_install_certificates
The embedded P-256 fixtures are synthetic public objects. The shared PFX
fixtures contain an artificial RSA private key and a public test password;
no real user secrets are included. Tests need only the standard library.
Every native PFX import is forced to NO_PERSIST, including install tests.
"""

import base64
import ctypes as ct
from contextlib import contextmanager, redirect_stdout
import io
import os
from pathlib import Path
import tempfile
import textwrap
import unittest
import warnings
from unittest.mock import Mock, patch

import install_certificates as installer
from extended_test_fixtures import TEST_PASSWORD, PFX_PASSWORD, PFX_EMPTY, PFX_CERT_ONLY, PFX_LEAF, PFX_ROOT


# DER encoded public fixtures. Generated once with cryptography, not at runtime.
FIXTURES = {
    "ROOT": (
        "MIIBhTCCASqgAwIBAgIBZDAKBggqhkjOPQQDAjAhMR8wHQYDVQQDDBZJbnN0YWxsZXIgZml4dHVy"
        "ZSByb290MB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowITEfMB0GA1UEAwwWSW5zdGFs"
        "bGVyIGZpeHR1cmUgcm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABH8QamHkWZZVNnX0JcM5"
        "8SzU7FVI6QDHHkmYfugdy+yEc9eVb/DDSM53Dli6dBAQG03ICs8onneATAG6m5iKD1+jUzBRMA8G"
        "A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFB6omIr0u/BmwptoLwvudbXjwKWOMB8GA1UdIwQYMBaA"
        "FB6omIr0u/BmwptoLwvudbXjwKWOMAoGCCqGSM49BAMCA0kAMEYCIQDEY7MrgIj454L2HhtIMW6d"
        "AZa9e7Mq9R+3Rw3WpaQmMgIhANBx0nN+fFgLSBvFF6AL91xbKrxH/fgCBGvzZgk3FY3c"
    ),
    "INTERMEDIATE": (
        "MIIBjTCCATKgAwIBAgIBZTAKBggqhkjOPQQDAjAhMR8wHQYDVQQDDBZJbnN0YWxsZXIgZml4dHVy"
        "ZSByb290MB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowKTEnMCUGA1UEAwweSW5zdGFs"
        "bGVyIGZpeHR1cmUgaW50ZXJtZWRpYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuPbnEmFL"
        "uR/soLyQTONkgq30417AgerA69AyFPQtrUe3ANSc1yH7eY6Qde+8W1cbwcQ1N4DUZXkiXWAJxNQj"
        "7aNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUcZ6OC5DmlO1j7QCHjseZ1O5dRbYwHwYD"
        "VR0jBBgwFoAUHqiYivS78GbCm2gvC+51tePApY4wCgYIKoZIzj0EAwIDSQAwRgIhAMFH7Nr5eTHE"
        "Tf8jiLhx3uTllJAmqsTrQcgBSCQGxDqcAiEA4hcVL6gC8v8R+jCARyJt5MROt1hpyuwtW+wrVkFM"
        "KrA="
    ),
    "LEAF": (
        "MIIBiDCCAS+gAwIBAgIBZjAKBggqhkjOPQQDAjApMScwJQYDVQQDDB5JbnN0YWxsZXIgZml4dHVy"
        "ZSBpbnRlcm1lZGlhdGUwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAhMR8wHQYDVQQD"
        "DBZJbnN0YWxsZXIgZml4dHVyZSBsZWFmMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGYi+cZHC"
        "TAnY8Djbq+ZkomMyGRjx6H1TYa2gghQnkoolzRXv9ycb5Js3xKm+R86cUTqgHSnfHSaDvkmd7VYI"
        "WqNQME4wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUMQl9cj5CT4Av2GaceA5ai9y5aogwHwYDVR0j"
        "BBgwFoAUcZ6OC5DmlO1j7QCHjseZ1O5dRbYwCgYIKoZIzj0EAwIDRwAwRAIgVhU6Rh4z4M9RkCgo"
        "OQikgOFSvFlL5Kma1Kx+P/CmwaUCIBQEQnY7PUawGgmd9PbE8Ll6HK6/w7PRI0N1f+h3nEZm"
    ),
    "SELF_SIGNED_LEAF": (
        "MIIBijCCATGgAwIBAgIBZzAKBggqhkjOPQQDAjAmMSQwIgYDVQQDDBtJbnN0YWxsZXIgZml4dHVy"
        "ZSBzZWxmIGxlYWYwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAmMSQwIgYDVQQDDBtJ"
        "bnN0YWxsZXIgZml4dHVyZSBzZWxmIGxlYWYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATunpcN"
        "NNisw+DpI5YQin4g3aPguiyhs+4Vdi+0OwzHolW7Ke/W9wG9wqy7axT7HqTYZLVNYfHR+lI0mALk"
        "dX7lo1AwTjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRjvV8CJx8WyWjTfXQdJOAec5qSwzAfBgNV"
        "HSMEGDAWgBRjvV8CJx8WyWjTfXQdJOAec5qSwzAKBggqhkjOPQQDAgNHADBEAiAbIdgaS2/JOPrb"
        "aBZzWms8n4CPVmJyY3AGs1wOaaXU6AIgFfDJXkiuqs/qFhSqx4xSJQjiQusUtO6pdmD+ipoDn3U="
    ),
    "SELF_ISSUED_CA": (
        "MIIBgzCCASqgAwIBAgIBaDAKBggqhkjOPQQDAjAhMR8wHQYDVQQDDBZJbnN0YWxsZXIgZml4dHVy"
        "ZSByb290MB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowITEfMB0GA1UEAwwWSW5zdGFs"
        "bGVyIGZpeHR1cmUgcm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDbCf7QDBkb4tzU9XLWT"
        "UtIkATfnD5vxE/Y3yjQkhWmp7fccKlCzWaL/pyE7eSv4LDW036JFrdGPVVsINq9OAQSjUzBRMA8G"
        "A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFNq8i7YXpL661mPUM7TDJcu3ecrcMB8GA1UdIwQYMBaA"
        "FB6omIr0u/BmwptoLwvudbXjwKWOMAoGCCqGSM49BAMCA0cAMEQCIGUa+lDo64BrRG7DXXQVTgOp"
        "qJTPBsxqbBa2l29LdNAPAiB3CXreGYJ9M1nt5gxSA6G1sdDOruk9uni1jFm0x3Qctg=="
    ),
    "CRL_OLD": (
        "MIHNMHUCAQEwCgYIKoZIzj0EAwIwITEfMB0GA1UEAwwWSW5zdGFsbGVyIGZpeHR1cmUgcm9vdBcN"
        "MjYxMTAxMDAwMDAwWhcNMzAwMTAxMDAwMDAwWqAjMCEwHwYDVR0jBBgwFoAUHqiYivS78GbCm2gv"
        "C+51tePApY4wCgYIKoZIzj0EAwIDSAAwRQIhAIIqqKhcIT1QtcOeykIzkCb1joegxlsnxt6kSu9b"
        "bV/yAiBktcYMjYRfjXiL4EPvYrVBpt7vs6F39RJIfQ+2YbgO8A=="
    ),
    "CRL_NEW": (
        "MIHOMHUCAQEwCgYIKoZIzj0EAwIwITEfMB0GA1UEAwwWSW5zdGFsbGVyIGZpeHR1cmUgcm9vdBcN"
        "MjYxMTAyMDAwMDAwWhcNMzAwMTAxMDAwMDAwWqAjMCEwHwYDVR0jBBgwFoAUHqiYivS78GbCm2gv"
        "C+51tePApY4wCgYIKoZIzj0EAwIDSQAwRgIhAJL+4k1yUdfN+B5xT3kchvLU1uIsxE45uj7bKXER"
        "wZ4DAiEAuLuSc/Gsp1WPd5XaMMGwEylWVblRvfNAbiwVCsnkfwk="
    ),
}


def der(name):
    return base64.b64decode(FIXTURES[name])


def pem(name):
    label = "X509 CRL" if name.startswith("CRL_") else "CERTIFICATE"
    return ("-----BEGIN {0}-----\n{1}\n-----END {0}-----\n".format(
        label, "\n".join(textwrap.wrap(FIXTURES[name], 64)))).encode("ascii")


def tlv(tag, value):
    """Minimal DER writer for test-only degenerate SignedData containers."""
    size = len(value)
    if size < 128:
        length = bytes([size])
    else:
        encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + length + value


def pkcs7(cert_names=("ROOT", "INTERMEDIATE", "LEAF"), crl_names=("CRL_OLD",), encoding="der"):
    signed_data_oid = bytes.fromhex("06092a864886f70d010702")
    data_oid = bytes.fromhex("06092a864886f70d010701")
    content = b"\x02\x01\x01\x31\x00" + tlv(0x30, data_oid)
    if cert_names:
        content += tlv(0xA0, b"".join(sorted(der(name) for name in cert_names)))
    if crl_names:
        content += tlv(0xA1, b"".join(sorted(der(name) for name in crl_names)))
    binary = tlv(0x30, signed_data_oid + tlv(0xA0, tlv(0x30, content + b"\x31\x00")))
    if encoding == "der":
        return binary
    text = "\n".join(textwrap.wrap(base64.b64encode(binary).decode("ascii"), 64))
    if encoding == "pem":
        text = "-----BEGIN PKCS7-----\n" + text + "\n-----END PKCS7-----\n"
    return text.encode("ascii")


def context_bytes(context):
    # CERT_CONTEXT and CRL_CONTEXT share this encoded-data prefix.
    class EncodedPrefix(ct.Structure):
        _fields_ = [("encoding", installer.wt.DWORD),
                    ("data", ct.POINTER(installer.wt.BYTE)),
                    ("size", installer.wt.DWORD)]

    prefix = ct.cast(context, ct.POINTER(EncodedPrefix)).contents
    return ct.string_at(prefix.data, prefix.size)


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.output = io.StringIO()
        self.redirect = redirect_stdout(self.output)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)

    def test_scan_is_nonrecursive_and_case_insensitive(self):
        suffixes = (".crt", ".cer", ".crl", ".pem", ".der", ".p7b", ".p7c", ".sst", ".pfx", ".p12")
        supported = ["a"+suffix for suffix in suffixes]
        supported += ["mixed.CeR", "mixed.PfX", "mixed.P7C", "mixed.PEM"]
        for name in supported + ["ignore.txt", "ignore.key"]:
            (self.directory / name).write_bytes(b"fixture")
        nested = self.directory / "nested"
        nested.mkdir()
        for suffix in suffixes:
            (nested / ("nested"+suffix)).write_bytes(b"fixture")
            (self.directory / ("directory"+suffix)).mkdir()
        expected = sorted(supported, key=lambda name: (name.casefold(), name))
        self.assertEqual([p.name for p in installer.find_files(self.directory)], expected)

    def make_api(self):
        api = Mock()

        @contextmanager
        def load_objects(path, location="user", dry_run=False, password_prompt=None):
            yield [(installer.CERT_QUERY_CONTENT_CERT, path.name)]

        @contextmanager
        def open_store(name, location):
            yield "memory-handle"

        api.load_objects.side_effect = load_objects
        api.open_store.side_effect = open_store
        api.select_store.side_effect = lambda kind, context, mode: "Root" if mode == "root" else "My"
        api.add.return_value = True
        return api

    def test_single_location_and_mode_apply_to_entire_batch(self):
        paths = [self.directory / "one.crt", self.directory / "two.crt"]
        for location in ("user", "machine"):
            for mode in ("auto", "root"):
                with self.subTest(location=location, mode=mode):
                    api = self.make_api()
                    result = installer.install_files(paths, api, location, mode)
                    self.assertEqual(result, installer.Results(installed=2))
                    self.assertEqual([call.args[2] for call in api.select_store.call_args_list],
                                     [mode, mode])
                    target = "Root" if mode == "root" else "My"
                    self.assertEqual([call.args for call in api.open_store.call_args_list],
                                     [(target, location), (target, location)])

    def test_dry_run_never_opens_or_adds_to_a_store(self):
        api = self.make_api()
        result = installer.install_files([self.directory / "one.crt", self.directory / "two.crl"],
                                         api, "machine", "root", dry_run=True)
        self.assertEqual(result, installer.Results(planned=2))
        api.open_store.assert_not_called()
        api.add.assert_not_called()

    def test_password_prompt_uses_getpass_and_rejects_visible_fallback(self):
        path = self.directory / "private.pfx"
        with patch.object(installer.getpass, "getpass", return_value=TEST_PASSWORD) as hidden:
            self.assertEqual(installer.prompt_pfx_password(path, 1), TEST_PASSWORD)
            hidden.assert_called_once()
        self.assertNotIn(TEST_PASSWORD, self.output.getvalue())

        def visible_fallback(prompt):
            warnings.warn("Cannot hide password", installer.getpass.GetPassWarning)
            raise AssertionError("Visible fallback must be prevented")

        with patch.object(installer.getpass, "getpass", side_effect=visible_fallback):
            with self.assertRaises(installer.FileCancelled):
                installer.prompt_pfx_password(path, 1)

    @unittest.skipUnless(os.name == "nt", "Windows command flow")
    def test_cancelled_pfx_makes_main_return_nonzero(self):
        (self.directory / "private.pfx").write_bytes(PFX_PASSWORD)
        with patch.object(installer, "__file__", str(self.directory / "install_certificates.py")), \
                patch.object(installer, "ask_choice", side_effect=["user", "auto"]), \
                patch.object(installer, "CryptoAPI"), \
                patch.object(installer, "install_files", return_value=installer.Results(cancelled=1)):
            self.assertEqual(installer.main(), 1)

    @unittest.skipUnless(os.name == "nt", "Windows command flow")
    def test_machine_without_admin_stops_before_api_is_created(self):
        (self.directory / "one.crt").write_bytes(der("ROOT"))
        with patch.object(installer, "__file__", str(self.directory / "install_certificates.py")), \
                patch.object(installer, "ask_choice", side_effect=["machine", "root"]) as ask, \
                patch.object(installer, "is_admin", return_value=False), \
                patch.object(installer, "CryptoAPI") as api:
            self.assertEqual(installer.main(), 1)
        self.assertEqual(ask.call_count, 2)
        api.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows command flow")
    def test_no_files_returns_before_prompt_or_api_creation(self):
        with patch.object(installer, "__file__", str(self.directory / "install_certificates.py")), \
                patch.object(installer, "ask_choice") as ask, \
                patch.object(installer, "CryptoAPI") as api:
            self.assertEqual(installer.main(), 0)
        ask.assert_not_called()
        api.assert_not_called()


@unittest.skipUnless(os.name == "nt", "Windows CryptoAPI integration")
class NativeMemoryStoreTests(unittest.TestCase):
    """Every store opened here must use CERT_STORE_PROV_MEMORY (provider 2)."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.api = installer.CryptoAPI()
        self.pfx_requests = []

        def memory_only_pfx(blob, password, flags):
            self.pfx_requests.append(flags)
            # A MEMORY destination does NOT stop PFXImportCertStore persisting keys.
            # Every native test forces ephemeral keys at the PFX-import boundary.
            return self.api._native_pfx_import(blob, password, flags | installer.PKCS12_NO_PERSIST_KEY)

        self.api.pfx_importer = memory_only_pfx
        self.handles = {}
        self.output = io.StringIO()
        self.redirect = redirect_stdout(self.output)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)
        native_open = self.api.dll.CertOpenStore

        def guarded_open(provider, encoding, crypt_provider, flags, parameter):
            # This assertion also blocks an accidental call to real open_store.
            self.assertEqual(provider, 2, "Tests may only open a memory store")
            return native_open(provider, encoding, crypt_provider, flags, parameter)

        self.open_guard = patch.object(self.api.dll, "CertOpenStore", side_effect=guarded_open)
        self.open_guard.start()
        self.addCleanup(self.open_guard.stop)
        self.addCleanup(self.close_memory_stores)
        # Batch code uses the production add/load logic, with only open_store replaced.
        self.api.open_store = Mock(side_effect=self.memory_store)

    @contextmanager
    def memory_store(self, name, location):
        key = (name, location)
        if key not in self.handles:
            handle = self.api.dll.CertOpenStore(2, 0, None, 0, None)
            if not handle:
                raise self.api._error("Cannot create test memory store")
            self.handles[key] = handle
        yield self.handles[key]

    def close_memory_stores(self):
        for handle in self.handles.values():
            self.assertTrue(self.api.dll.CertCloseStore(handle, 0))
        self.handles.clear()

    def write_fixture(self, name, as_pem=False, suffix=None):
        suffix = suffix or (".crl" if name.startswith("CRL_") else ".crt")
        path = self.directory / ("тест_" + name + ("_pem" if as_pem else "_der") + suffix)
        path.write_bytes(pem(name) if as_pem else der(name))
        return path

    def stored_objects(self, handle, crl=False):
        enum = getattr(self.api.dll, "CertEnumCRLsInStore" if crl else "CertEnumCertificatesInStore")
        enum.argtypes = [installer.wt.HANDLE, ct.c_void_p]
        enum.restype = ct.c_void_p

        class EncodedPrefix(ct.Structure):
            _fields_ = [("encoding", installer.wt.DWORD),
                        ("data", ct.POINTER(installer.wt.BYTE)),
                        ("size", installer.wt.DWORD)]

        result, previous = [], None
        while True:
            current = enum(handle, previous)  # Frees previous, including on end.
            if not current:
                break
            prefix = ct.cast(current, ct.POINTER(EncodedPrefix)).contents
            result.append(ct.string_at(prefix.data, prefix.size))
            previous = current
        return result

    def test_production_store_opener_selects_exact_scope_without_native_open(self):
        for location, flag in (("user", installer.CERT_SYSTEM_STORE_CURRENT_USER),
                               ("machine", installer.CERT_SYSTEM_STORE_LOCAL_MACHINE)):
            with self.subTest(location=location), \
                    patch.object(self.api.dll, "CertOpenStore", return_value=1234) as opened, \
                    patch.object(self.api.dll, "CertCloseStore", return_value=True) as closed:
                # Invoke the production method explicitly; the native call is mocked.
                with installer.CryptoAPI.open_store(self.api, "Root", location) as handle:
                    self.assertEqual(handle, 1234)
                args = opened.call_args.args
                self.assertEqual(args[:4], (installer.CERT_STORE_PROV_SYSTEM_W, 0, None, flag))
                self.assertEqual(args[4].value, "Root")
                opened.assert_called_once()
                closed.assert_called_once_with(1234, 0)

    def test_missing_and_legacy_basic_constraints_follow_declared_policy(self):
        info = installer.CERT_INFO()
        self.assertFalse(self.api._is_ca(info))
        for encoded, expected in ((b"\x30\x04\x03\x02\x07\x80", True),
                                  (b"\x30\x04\x03\x02\x06\x40", False)):
            with self.subTest(encoded=encoded.hex()):
                data = (installer.wt.BYTE * len(encoded)).from_buffer_copy(encoded)
                extension = installer.EXTENSION()
                extension.pszObjId = b"2.5.29.10"  # Legacy Basic Constraints v1.
                extension.Value = installer.BLOB(
                    len(encoded), ct.cast(data, ct.POINTER(installer.wt.BYTE)))
                extensions = (installer.EXTENSION * 1)(extension)
                info.cExtension = 1
                info.rgExtension = extensions
                self.assertEqual(self.api._is_ca(info), expected)

    def test_der_and_pem_auto_classification_including_signature_edge_cases(self):
        expected = {"ROOT": "Root", "INTERMEDIATE": "CA", "LEAF": "My",
                    "SELF_SIGNED_LEAF": "My", "SELF_ISSUED_CA": "CA",
                    "CRL_OLD": "CA"}
        for name, store in expected.items():
            for as_pem in (False, True):
                with self.subTest(name=name, pem=as_pem):
                    with self.api.load(self.write_fixture(name, as_pem)) as (kind, context):
                        self.assertEqual(kind, installer.CERT_QUERY_CONTENT_CRL
                                         if name.startswith("CRL_") else installer.CERT_QUERY_CONTENT_CERT)
                        self.assertEqual(self.api.select_store(kind, context, "auto"), store)
                        self.assertEqual(self.api.select_store(kind, context, "root"), "Root")
        self.api.open_store.assert_not_called()

    def test_actual_content_controls_type_instead_of_filename_suffix(self):
        for name, suffix, expected in (("ROOT", ".crl", installer.CERT_QUERY_CONTENT_CERT),
                                       ("CRL_OLD", ".crt", installer.CERT_QUERY_CONTENT_CRL)):
            with self.subTest(name=name):
                with self.api.load(self.write_fixture(name, suffix=suffix)) as (kind, _):
                    self.assertEqual(kind, expected)

    def test_unsupported_self_signature_is_an_error_not_an_intermediate(self):
        error_code = 0x80090008  # NTE_BAD_ALGID, unavailable algorithm/provider.

        def unsupported(*args):
            ct.set_last_error(ct.c_long(error_code).value)
            return False

        with self.api.load(self.write_fixture("ROOT")) as (kind, context), \
                patch.object(self.api.dll, "CryptVerifyCertificateSignatureEx", side_effect=unsupported):
            with self.assertRaises(OSError) as caught:
                self.api.select_store(kind, context, "auto")
        self.assertEqual(caught.exception.errno & 0xFFFFFFFF, error_code)
        self.assertIn("0x80090008", str(caught.exception))
        self.api.open_store.assert_not_called()

    def test_corrupt_file_reports_error_and_continues_native_batch(self):
        damaged = self.directory / "bad.crt"
        damaged.write_bytes(b"this is not a certificate")
        paths = [damaged, self.write_fixture("ROOT"), self.write_fixture("LEAF", as_pem=True)]
        result = installer.install_files(paths, self.api, "user", "auto")
        self.assertEqual(result, installer.Results(installed=2, errors=1))
        self.assertEqual(set(self.handles), {("Root", "user"), ("My", "user")})
        self.assertEqual(self.stored_objects(self.handles[("Root", "user")]), [der("ROOT")])
        self.assertEqual(self.stored_objects(self.handles[("My", "user")]), [der("LEAF")])

    def test_cer_der_and_pem_imports_use_content_and_memory_stores(self):
        self.write_fixture("ROOT", suffix=".cer")
        self.write_fixture("LEAF", as_pem=True, suffix=".CeR")
        result = installer.install_files(installer.find_files(self.directory), self.api, "user", "auto")
        self.assertEqual(result, installer.Results(installed=2))
        self.assertEqual(set(self.handles), {("Root", "user"), ("My", "user")})
        self.assertEqual(self.stored_objects(self.handles[("Root", "user")]), [der("ROOT")])
        self.assertEqual(self.stored_objects(self.handles[("My", "user")]), [der("LEAF")])

    def test_duplicate_certificate_is_skipped_even_if_file_encoding_changes(self):
        files = [self.write_fixture("ROOT"), self.write_fixture("ROOT", as_pem=True)]
        result = installer.install_files(files, self.api, "machine", "root")
        self.assertEqual(result, installer.Results(installed=1, skipped=1))
        self.assertEqual(self.stored_objects(self.handles[("Root", "machine")]), [der("ROOT")])

    def test_crl_duplicate_and_older_skip_but_newer_replaces_in_memory(self):
        old = self.write_fixture("CRL_OLD")
        same = self.write_fixture("CRL_OLD", as_pem=True)
        new = self.write_fixture("CRL_NEW", as_pem=True)
        result = installer.install_files([old, same, new, old], self.api, "user", "auto")
        self.assertEqual(result, installer.Results(installed=2, skipped=2))
        self.assertEqual(self.stored_objects(self.handles[("CA", "user")], crl=True), [der("CRL_NEW")])

    def write_pkcs7(self, encoding="der", cert_names=("ROOT", "INTERMEDIATE", "LEAF"),
                    crl_names=("CRL_OLD",), filename=None):
        path = self.directory / (filename or ("цепочка_" + encoding + ".p7b"))
        path.write_bytes(pkcs7(cert_names, crl_names, encoding))
        return path

    def test_p7b_loads_every_certificate_and_crl_in_der_pem_and_base64(self):
        expected = {
            installer.CERT_QUERY_CONTENT_CERT: {der("ROOT"), der("INTERMEDIATE"), der("LEAF")},
            installer.CERT_QUERY_CONTENT_CRL: {der("CRL_OLD")},
        }
        for encoding in ("der", "pem", "base64"):
            with self.subTest(encoding=encoding):
                with self.api.load_objects(self.write_pkcs7(encoding)) as objects:
                    actual = {}
                    count = 0
                    for kind, context in objects:
                        actual.setdefault(kind, set()).add(context_bytes(context))
                        count += 1
                    self.assertEqual(count, 4)
                    self.assertEqual(actual, expected)
        self.api.open_store.assert_not_called()

    def test_p7b_certificate_only_and_crl_only_containers(self):
        for cert_names, crl_names in ((("ROOT", "INTERMEDIATE", "LEAF"), ()),
                                      ((), ("CRL_OLD",))):
            with self.subTest(cert_names=cert_names, crl_names=crl_names):
                path = self.write_pkcs7(cert_names=cert_names, crl_names=crl_names)
                with self.api.load_objects(path) as objects:
                    actual = {context_bytes(context) for _, context in objects}
                self.assertEqual(actual, {der(name) for name in cert_names + crl_names})
        self.api.open_store.assert_not_called()

    def test_p7b_imports_all_objects_in_auto_and_root_for_both_scopes(self):
        path = self.write_pkcs7()
        for location in ("user", "machine"):
            for mode in ("auto", "root"):
                with self.subTest(location=location, mode=mode):
                    self.close_memory_stores()
                    self.api.open_store.reset_mock()
                    result = installer.install_files([path], self.api, location, mode)
                    self.assertEqual(result, installer.Results(installed=4))
                    if mode == "auto":
                        certs_by_store = {"Root": {der("ROOT")}, "CA": {der("INTERMEDIATE")},
                                          "My": {der("LEAF")}}
                    else:
                        certs_by_store = {"Root": {der("ROOT"), der("INTERMEDIATE"), der("LEAF")}}
                    self.assertEqual(set(self.handles), {(store, location) for store in certs_by_store})
                    for store, expected in certs_by_store.items():
                        self.assertEqual(set(self.stored_objects(self.handles[(store, location)])), expected)
                    crl_store = "CA" if mode == "auto" else "Root"
                    self.assertEqual(self.stored_objects(self.handles[(crl_store, location)], crl=True),
                                     [der("CRL_OLD")])
                    self.assertEqual([call.args[1] for call in self.api.open_store.call_args_list],
                                     [location] * 4)

    def test_p7b_duplicates_are_skipped_across_container_formats_and_standalone_file(self):
        paths = [self.write_pkcs7("pem"), self.write_fixture("ROOT"), self.write_pkcs7("der")]
        result = installer.install_files(paths, self.api, "user", "auto")
        self.assertEqual(result, installer.Results(installed=4, skipped=5))
        self.assertEqual(self.stored_objects(self.handles[("Root", "user")]), [der("ROOT")])
        self.assertEqual(self.stored_objects(self.handles[("CA", "user")], crl=True), [der("CRL_OLD")])

    def test_empty_and_corrupt_p7b_report_errors_then_continue_with_valid_bundle(self):
        empty = self.write_pkcs7(cert_names=(), crl_names=(), filename="empty.p7b")
        corrupt = self.directory / "corrupt.p7b"
        corrupt.write_bytes(b"not PKCS7")
        result = installer.install_files([empty, corrupt, self.write_pkcs7()], self.api, "user", "auto")
        self.assertEqual(result, installer.Results(installed=4, errors=2))

    def test_p7b_dry_run_counts_objects_without_store_open_or_add(self):
        self.api.add = Mock(wraps=self.api.add)
        paths = [self.write_pkcs7(encoding) for encoding in ("der", "pem", "base64")]
        result = installer.install_files(paths, self.api, "machine", "root", dry_run=True)
        self.assertEqual(result, installer.Results(planned=12))
        self.api.open_store.assert_not_called()
        self.api.add.assert_not_called()
        self.assertFalse(self.handles)

    def test_p7b_one_object_error_does_not_stop_other_objects(self):
        path = self.write_pkcs7()
        for operation in ("select_store", "add"):
            with self.subTest(operation=operation):
                self.close_memory_stores()
                native_method = getattr(self.api, operation)
                seen = []

                def fail_one(*args):
                    context = args[1] if operation == "select_store" else args[2]
                    encoded = context_bytes(context)
                    seen.append(encoded)
                    if encoded == der("ROOT"):
                        raise OSError("synthetic object failure")
                    return native_method(*args)

                with patch.object(self.api, operation, side_effect=fail_one):
                    result = installer.install_files([path], self.api, "user", "auto")
                self.assertEqual(result, installer.Results(installed=3, errors=1))
                self.assertEqual(set(seen), {der("ROOT"), der("INTERMEDIATE"), der("LEAF"), der("CRL_OLD")})
                self.assertEqual(len(seen), 4)
                self.assertEqual(self.stored_objects(self.handles[("My", "user")]), [der("LEAF")])
                self.assertEqual(self.stored_objects(self.handles[("CA", "user")], crl=True), [der("CRL_OLD")])

    def test_p7b_container_resources_are_released_after_early_consumer_exit(self):
        native_close = self.api.dll.CertCloseStore
        close_results = []

        def checked_close(handle, flags):
            # CHECK_FLAG reports leaked contexts and still closes the query store.
            result = native_close(handle, flags | 2)
            close_results.append(bool(result))
            return result

        with patch.object(self.api.dll, "CertCloseStore", side_effect=checked_close):
            with self.assertRaisesRegex(RuntimeError, "consumer stopped"):
                with self.api.load_objects(self.write_pkcs7()) as objects:
                    kind, context = next(iter(objects))
                    self.assertIn(kind, (installer.CERT_QUERY_CONTENT_CERT, installer.CERT_QUERY_CONTENT_CRL))
                    self.assertTrue(context_bytes(context))
                    raise RuntimeError("consumer stopped")
        self.assertTrue(close_results)
        self.assertTrue(all(close_results), "PKCS7 store retained native object contexts")
        self.assertFalse(self.handles)

    def test_pem_bundle_imports_all_certificate_crl_and_pkcs7_blocks(self):
        path = self.directory / "bundle.pem"
        path.write_bytes(pem("ROOT") + pem("CRL_OLD") + pkcs7(encoding="pem"))
        result = installer.install_files([path], self.api, "user", "auto")
        self.assertEqual(result, installer.Results(installed=4, skipped=2))
        self.assertEqual(self.stored_objects(self.handles[("Root", "user")]), [der("ROOT")])
        self.assertEqual(self.stored_objects(self.handles[("My", "user")]), [der("LEAF")])
        self.assertEqual(self.stored_objects(self.handles[("CA", "user")], crl=True), [der("CRL_OLD")])

    def test_pem_corrupt_unsupported_and_unterminated_blocks_do_not_hide_valid_neighbors(self):
        bad = b"-----BEGIN CERTIFICATE-----\ninvalid$\n-----END CERTIFICATE-----\n"
        private = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
        missing = b"-----BEGIN CERTIFICATE-----\nAAAA\n"
        path = self.directory / "mixed.pem"
        path.write_bytes(b"-----BEGIN BROKEN---\n" + pem("ROOT") + bad + pem("LEAF") +
                         private + pem("CRL_OLD") + missing + pem("INTERMEDIATE"))
        result = installer.install_files([path], self.api, "user", "auto")
        self.assertEqual(result, installer.Results(installed=4, errors=4))
        self.assertEqual(self.stored_objects(self.handles[("My", "user")]), [der("LEAF")])
        self.assertEqual(self.stored_objects(self.handles[("CA", "user")]), [der("INTERMEDIATE")])

    def test_der_pem_and_p7c_aliases_are_imported_by_content(self):
        root = self.write_fixture("ROOT", suffix=".DER")
        leaf = self.write_fixture("LEAF", as_pem=True, suffix=".PeM")
        container = self.write_pkcs7(filename="chain.P7C")
        result = installer.install_files([root, leaf, container], self.api, "user", "auto")
        self.assertEqual(result, installer.Results(installed=4, skipped=2))

    def serialized_store(self, pem_marker=False):
        handle = self.api.dll.CertOpenStore(2, 0, None, 0, None)
        self.assertTrue(handle)
        try:
            for name in ("ROOT", "CRL_OLD"):
                with self.api.load(self.write_fixture(name)) as (kind, context):
                    self.assertTrue(self.api.add(handle, kind, context))
            if pem_marker:
                context = self.api.dll.CertEnumCertificatesInStore(handle, None)
                self.assertTrue(context)
                try:
                    marker = b"binary property -----BEGIN CERTIFICATE----- marker"
                    buffer = (installer.wt.BYTE * len(marker)).from_buffer_copy(marker)
                    value = installer.BLOB(len(marker), buffer)
                    setter = self.api.dll.CertSetCertificateContextProperty
                    setter.argtypes = [ct.c_void_p, installer.wt.DWORD, installer.wt.DWORD, ct.c_void_p]
                    setter.restype = installer.wt.BOOL
                    self.assertTrue(setter(context, 0x8001, 0, ct.byref(value)))
                finally:
                    self.api.dll.CertFreeCertificateContext(context)
            save = self.api.dll.CertSaveStore
            save.argtypes = [installer.wt.HANDLE, installer.wt.DWORD, installer.wt.DWORD,
                             installer.wt.DWORD, ct.c_void_p, installer.wt.DWORD]
            save.restype = installer.wt.BOOL
            blob = installer.BLOB()
            self.assertTrue(save(handle, 0x10001, 1, 2, ct.byref(blob), 0))
            buffer = (installer.wt.BYTE * blob.cbData)()
            blob.pbData = buffer
            self.assertTrue(save(handle, 0x10001, 1, 2, ct.byref(blob), 0))
            return ct.string_at(blob.pbData, blob.cbData)
        finally:
            self.assertTrue(self.api.dll.CertCloseStore(handle, 0))

    def test_pem_allows_openssl_bag_attributes_subject_issuer_and_comments(self):
        path = self.directory / "openssl.pem"
        path.write_bytes(b"Bag Attributes\n    friendlyName: Example\nsubject=CN=example\nissuer=CN=root\n# comment\n" +
                         pem("ROOT") + b"\nBag Attributes\nsubject=CN=leaf\nissuer=CN=root\n" +
                         pem("LEAF") + b"\n# trailing comment\n")
        self.assertEqual(installer.install_files([path], self.api, "user", "auto"), installer.Results(installed=2))

    def test_pem_labels_reject_pfx_sst_and_mismatched_content_without_importing_keys(self):
        cases = ((b"CERTIFICATE", PFX_PASSWORD), (b"CERTIFICATE", self.serialized_store()),
                 (b"CERTIFICATE", der("CRL_OLD")), (b"X509 CRL", der("ROOT")),
                 (b"PKCS7", der("ROOT")))
        for label, data in cases:
            with self.subTest(label=label, data_length=len(data)):
                self.close_memory_stores()
                self.pfx_requests.clear()
                path = self.directory / "mislabeled.pem"
                path.write_bytes(b"-----BEGIN " + label + b"-----\n" + base64.b64encode(data) +
                                 b"\n-----END " + label + b"-----\n" + pem("LEAF"))
                prompt = Mock(side_effect=AssertionError("Mislabeled PEM must never enter the PFX importer"))
                result = installer.install_files([path], self.api, "user", "auto", password_prompt=prompt)
                self.assertEqual(result, installer.Results(installed=1, errors=1))
                self.assertFalse(self.pfx_requests)
                prompt.assert_not_called()
                self.assertEqual(self.stored_objects(self.handles[("My", "user")]), [der("LEAF")])

    def test_binary_sst_with_pem_marker_property_remains_a_binary_store(self):
        data = self.serialized_store(pem_marker=True)
        self.assertIn(b"-----BEGIN", data)
        path = self.directory / "binary.sst"
        path.write_bytes(data)
        result = installer.install_files([path], self.api, "user", "auto")
        self.assertEqual(result, installer.Results(installed=2))
        self.assertEqual(self.stored_objects(self.handles[("Root", "user")]), [der("ROOT")])
        self.assertEqual(self.stored_objects(self.handles[("CA", "user")], crl=True), [der("CRL_OLD")])

    def test_binary_pkcs7_payload_with_pem_marker_remains_a_container(self):
        signed_data_oid = bytes.fromhex("06092a864886f70d010702")
        data_oid = bytes.fromhex("06092a864886f70d010701")
        content = b"\x02\x01\x01\x31\x00" + tlv(0x30, data_oid +
                  tlv(0xA0, tlv(0x04, b"-----BEGIN CERTIFICATE----- binary payload")))
        content += tlv(0xA0, der("ROOT")) + b"\x31\x00"
        data = tlv(0x30, signed_data_oid + tlv(0xA0, tlv(0x30, content)))
        path = self.directory / "binary.p7c"
        path.write_bytes(data)
        self.assertEqual(installer.install_files([path], self.api, "user", "auto"), installer.Results(installed=1))
        self.assertEqual(self.stored_objects(self.handles[("Root", "user")]), [der("ROOT")])

    def test_sst_store_enumerates_certificates_and_crls_and_skips_duplicates(self):
        path = self.directory / "store.SST"
        path.write_bytes(self.serialized_store())
        result = installer.install_files([path, path], self.api, "machine", "root")
        self.assertEqual(result, installer.Results(installed=2, skipped=2))
        self.assertEqual(self.stored_objects(self.handles[("Root", "machine")]), [der("ROOT")])
        self.assertEqual(self.stored_objects(self.handles[("Root", "machine")], crl=True), [der("CRL_OLD")])

    def write_pfx(self, data=PFX_PASSWORD, name="private.pfx"):
        path = self.directory / name
        path.write_bytes(data)
        return path

    def assert_ephemeral_source_key_works(self, context):
        acquire = self.api.dll.CryptAcquireCertificatePrivateKey
        acquire.argtypes = [ct.c_void_p, installer.wt.DWORD, ct.c_void_p,
                            ct.POINTER(ct.c_size_t), ct.POINTER(installer.wt.DWORD),
                            ct.POINTER(installer.wt.BOOL)]
        acquire.restype = installer.wt.BOOL
        key, spec, release = ct.c_size_t(), installer.wt.DWORD(), installer.wt.BOOL()
        # Cache + silent + allow CNG. The source context owns the cached key.
        self.assertTrue(acquire(context, 0x1 | 0x40 | 0x10000, None,
                                ct.byref(key), ct.byref(spec), ct.byref(release)))
        self.assertTrue(key.value)
        if release.value:
            if spec.value == 0xFFFFFFFF:
                ncrypt = ct.WinDLL("ncrypt")
                ncrypt.NCryptFreeObject.argtypes = [ct.c_size_t]
                self.assertEqual(ncrypt.NCryptFreeObject(key), 0)
            else:
                advapi = ct.WinDLL("advapi32")
                advapi.CryptReleaseContext.argtypes = [ct.c_size_t, installer.wt.DWORD]
                self.assertTrue(advapi.CryptReleaseContext(key, 0))

    def test_pfx_native_ephemeral_import_contains_a_usable_private_key(self):
        found = set()
        with self.api.load_objects(self.write_pfx(), dry_run=True,
                                   password_prompt=lambda path, attempt: TEST_PASSWORD) as objects:
            for kind, context in objects:
                self.assertEqual(kind, installer.CERT_QUERY_CONTENT_CERT)
                found.add(context_bytes(context))
                if context_bytes(context) == PFX_LEAF:
                    self.assert_ephemeral_source_key_works(context)
        self.assertEqual(found, {PFX_LEAF, PFX_ROOT})
        self.assertEqual(self.pfx_requests, [installer.CRYPT_USER_KEYSET | installer.PKCS12_INCLUDE_EXTENDED_PROPERTIES | installer.PKCS12_NO_PERSIST_KEY])
        self.api.open_store.assert_not_called()

    def test_pfx_password_retries_without_logging_password_or_wrong_input(self):
        prompt = Mock(side_effect=["wrong-private-input", TEST_PASSWORD])
        result = installer.install_files([self.write_pfx()], self.api, "user", "auto", password_prompt=prompt)
        self.assertEqual(result, installer.Results(installed=2))
        self.assertEqual([call.args[1] for call in prompt.call_args_list], [1, 2])
        self.assertNotIn(TEST_PASSWORD, self.output.getvalue())
        self.assertNotIn("wrong-private-input", self.output.getvalue())
        self.assertEqual(self.stored_objects(self.handles[("My", "user")]), [PFX_LEAF])
        self.assertEqual(self.stored_objects(self.handles[("Root", "user")]), [PFX_ROOT])

    def test_pfx_empty_and_null_passwords_do_not_prompt(self):
        native_verify = self.api._verify_pfx_password
        for null_only in (False, True):
            with self.subTest(null_only=null_only):
                self.close_memory_stores()
                prompt = Mock(side_effect=AssertionError("Empty/null PFX must not prompt"))
                verifier = (lambda blob, password: password is None and native_verify(blob, password)) if null_only else native_verify
                with patch.object(self.api, "_verify_pfx_password", side_effect=verifier):
                    result = installer.install_files([self.write_pfx(PFX_EMPTY, "empty.p12")], self.api,
                                                     "user", "auto", password_prompt=prompt)
                self.assertEqual(result, installer.Results(installed=2))
                prompt.assert_not_called()

    def test_pfx_password_cancel_eof_or_ctrl_c_skips_only_one_file(self):
        for cancellation in (None, EOFError(), KeyboardInterrupt()):
            with self.subTest(cancellation=type(cancellation).__name__):
                self.close_memory_stores()
                self.pfx_requests.clear()
                prompt = Mock(return_value=None) if cancellation is None else Mock(side_effect=cancellation)
                result = installer.install_files([self.write_pfx(), self.write_fixture("ROOT")], self.api,
                                                 "user", "auto", password_prompt=prompt)
                self.assertEqual(result, installer.Results(installed=1, cancelled=1))
                self.assertFalse(self.pfx_requests)
                self.assertEqual(self.stored_objects(self.handles[("Root", "user")]), [der("ROOT")])

    def test_pfx_install_scope_mode_and_nonexportable_no_overwrite_flags(self):
        for location, scope in (("user", installer.CRYPT_USER_KEYSET), ("machine", installer.CRYPT_MACHINE_KEYSET)):
            for mode in ("auto", "root"):
                with self.subTest(location=location, mode=mode):
                    self.close_memory_stores()
                    self.pfx_requests.clear()
                    result = installer.install_files([self.write_pfx()], self.api, location, mode,
                                                     password_prompt=lambda path, attempt: TEST_PASSWORD)
                    self.assertEqual(result, installer.Results(installed=2))
                    self.assertEqual(self.pfx_requests, [scope | installer.PKCS12_INCLUDE_EXTENDED_PROPERTIES])
                    self.assertEqual({key[1] for key in self.handles}, {location})
                    self.assertEqual({key[0] for key in self.handles}, {"Root"} if mode == "root" else {"Root", "My"})
                    # Neither CRYPT_EXPORTABLE=1 nor PKCS12_ALLOW_OVERWRITE_KEY=0x4000.
                    self.assertFalse(self.pfx_requests[0] & (1 | 0x4000))

    def test_pfx_dry_run_forces_no_persistence_and_never_opens_targets(self):
        self.api.add = Mock(wraps=self.api.add)
        for location, scope in (("user", installer.CRYPT_USER_KEYSET), ("machine", installer.CRYPT_MACHINE_KEYSET)):
            self.pfx_requests.clear()
            paths = [self.write_pfx(), self.write_pfx(PFX_EMPTY, "empty.p12"),
                     self.write_pfx(PFX_CERT_ONLY, "certificate_only.pfx")]
            result = installer.install_files(paths, self.api, location, "auto", dry_run=True,
                                             password_prompt=lambda path, attempt: TEST_PASSWORD)
            self.assertEqual(result, installer.Results(planned=6))
            self.assertEqual(self.pfx_requests, [scope | installer.PKCS12_INCLUDE_EXTENDED_PROPERTIES | installer.PKCS12_NO_PERSIST_KEY] * 3)
        self.api.open_store.assert_not_called()
        self.api.add.assert_not_called()
        self.assertFalse(self.handles)

    def test_pfx_duplicate_public_certificate_receives_key_provider_association(self):
        class ProviderInfo(ct.Structure):
            _fields_ = [("container", installer.wt.LPWSTR), ("provider", installer.wt.LPWSTR),
                        ("provider_type", installer.wt.DWORD), ("flags", installer.wt.DWORD),
                        ("parameter_count", installer.wt.DWORD), ("parameters", ct.c_void_p),
                        ("key_spec", installer.wt.DWORD)]

        plain = self.directory / "public.cer"
        plain.write_bytes(PFX_LEAF)
        self.assertEqual(installer.install_files([plain], self.api, "user", "auto"), installer.Results(installed=1))
        original_importer = self.api.pfx_importer
        synthetic_container = "TEST-ONLY-NO-CONTAINER-WAS-CREATED"
        setter = self.api.dll.CertSetCertificateContextProperty
        setter.argtypes = [ct.c_void_p, installer.wt.DWORD, installer.wt.DWORD, ct.c_void_p]
        setter.restype = installer.wt.BOOL

        def ephemeral_with_synthetic_provider(blob, password, flags):
            handle = original_importer(blob, password, flags)  # Forces NO_PERSIST.
            self.assertTrue(handle)
            objects = self.api._store_objects(handle)
            try:
                for _, context in objects:
                    if context_bytes(context) == PFX_LEAF:
                        self.assert_ephemeral_source_key_works(context)
                        # Production uses persisted KEY_PROV_INFO, not ephemeral KEY_CONTEXT.
                        # Set harmless metadata to exercise its native merge without key files.
                        info = ProviderInfo(synthetic_container, "Microsoft Enhanced Cryptographic Provider v1.0",
                                            1, 0, 0, None, 1)
                        self.assertTrue(setter(context, installer.CERT_KEY_PROV_INFO_PROP_ID, 0, ct.byref(info)))
            finally:
                objects.close()
            return handle

        self.api.pfx_importer = ephemeral_with_synthetic_provider
        result = installer.install_files([self.write_pfx()], self.api, "user", "auto",
                                         password_prompt=lambda path, attempt: TEST_PASSWORD)
        self.assertEqual(result, installer.Results(installed=2))
        self.assertEqual(self.stored_objects(self.handles[("My", "user")]), [PFX_LEAF])
        # Read the destination metadata while its native context is alive.
        context = self.api.dll.CertEnumCertificatesInStore(self.handles[("My", "user")], None)
        self.assertTrue(context)
        try:
            size = installer.wt.DWORD()
            getter = self.api.dll.CertGetCertificateContextProperty
            self.assertTrue(getter(context, installer.CERT_KEY_PROV_INFO_PROP_ID, None, ct.byref(size)))
            buffer = ct.create_string_buffer(size.value)
            self.assertTrue(getter(context, installer.CERT_KEY_PROV_INFO_PROP_ID, buffer, ct.byref(size)))
            self.assertEqual(ct.cast(buffer, ct.POINTER(ProviderInfo)).contents.container, synthetic_container)
        finally:
            self.api.dll.CertFreeCertificateContext(context)
        self.assertEqual(installer.install_files([plain], self.api, "user", "auto"), installer.Results(skipped=1))

    def test_native_dry_run_validates_files_without_opening_memory_or_system_stores(self):
        self.api.add = Mock(wraps=self.api.add)
        paths = [self.write_fixture("ROOT"), self.write_fixture("CRL_OLD", as_pem=True)]
        result = installer.install_files(paths, self.api, "machine", "root", dry_run=True)
        self.assertEqual(result, installer.Results(planned=2))
        self.api.open_store.assert_not_called()
        self.api.add.assert_not_called()
        self.assertFalse(self.handles)


if __name__ == "__main__":
    unittest.main()
