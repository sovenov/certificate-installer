#include "certificate_import.h"

#include <algorithm>
#include <cstring>
#include <exception>
#include <limits>
#include <utility>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace certinstaller {
namespace {

const DWORD kInvalidSignature = 0xC000A000UL;
const DWORD kExpectedContent = CERT_QUERY_CONTENT_FLAG_CERT |
                               CERT_QUERY_CONTENT_FLAG_CRL |
                               CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
                               CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE;
const DWORD kExpectedFormat = CERT_QUERY_FORMAT_FLAG_BINARY |
                              CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED;

class BackendError : public std::exception {
public:
    explicit BackendError(std::wstring message) : message_(std::move(message)) {}
    const char* what() const noexcept override { return "Certificate import failed"; }
    const std::wstring& message() const noexcept { return message_; }

private:
    std::wstring message_;
};

class PasswordCancelled : public std::exception {};

struct PasswordBuffer {
    std::wstring value;
    ~PasswordBuffer() {
        if (!value.empty()) SecureZeroMemory(&value[0], value.size() * sizeof(wchar_t));
    }
    PasswordBuffer() = default;
    PasswordBuffer(const PasswordBuffer&) = delete;
    PasswordBuffer& operator=(const PasswordBuffer&) = delete;
};

struct FileBytes {
    std::vector<BYTE> value;
    ~FileBytes() {
        // An unencrypted PFX can contain private key material.
        if (!value.empty()) SecureZeroMemory(value.data(), value.size());
    }
};

class FileHandle {
public:
    explicit FileHandle(HANDLE value) noexcept : value_(value) {}
    ~FileHandle() { if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
    HANDLE get() const noexcept { return value_; }
private:
    HANDLE value_;
};

class StoreHandle {
public:
    explicit StoreHandle(HCERTSTORE value = nullptr) noexcept : value_(value) {}
    ~StoreHandle() { if (value_) CertCloseStore(value_, 0); }
    StoreHandle(const StoreHandle&) = delete;
    StoreHandle& operator=(const StoreHandle&) = delete;
    HCERTSTORE get() const noexcept { return value_; }

private:
    HCERTSTORE value_;
};

class LocalMemory {
public:
    explicit LocalMemory(void* value) noexcept : value_(value) {}
    ~LocalMemory() { if (value_) LocalFree(value_); }
    LocalMemory(const LocalMemory&) = delete;
    LocalMemory& operator=(const LocalMemory&) = delete;

private:
    void* value_;
};

template <typename Context>
class ContextHandle {
public:
    using Releaser = BOOL (WINAPI*)(const Context*);

    explicit ContextHandle(Releaser releaser) noexcept
        : value_(nullptr), releaser_(releaser) {}
    ~ContextHandle() { if (value_) releaser_(value_); }
    ContextHandle(const ContextHandle&) = delete;
    ContextHandle& operator=(const ContextHandle&) = delete;

    const Context* get() const noexcept { return value_; }
    const Context* release() noexcept {
        const Context* value = value_;
        value_ = nullptr;
        return value;
    }
    void reset(const Context* value) noexcept {
        if (value_) releaser_(value_);
        value_ = value;
    }

private:
    const Context* value_;
    Releaser releaser_;
};

BackendError WindowsFailure(const std::wstring& operation, DWORD error) {
    return BackendError(operation + L": " + FormatWindowsError(error));
}

std::wstring ExceptionMessage(const std::exception& exception) {
    const BackendError* backend = dynamic_cast<const BackendError*>(&exception);
    if (backend) return backend->message();
    const char* text = exception.what();
    if (!text || !*text) return L"Неизвестная ошибка";
    int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, nullptr, 0);
    UINT encoding = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    if (!required) {
        encoding = CP_ACP;
        flags = 0;
        required = MultiByteToWideChar(encoding, flags, text, -1, nullptr, 0);
    }
    if (!required) return L"Неизвестная ошибка";
    std::vector<wchar_t> buffer(static_cast<std::size_t>(required));
    if (!MultiByteToWideChar(encoding, flags, text, -1, buffer.data(), required)) {
        return L"Неизвестная ошибка";
    }
    return std::wstring(buffer.data());
}

void Emit(const LogSink& log, const std::wstring& message) {
    if (log) log(message);
}

std::wstring FileName(const std::wstring& path) {
    const std::wstring::size_type slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

std::wstring FullPathForLog(const std::wstring& path) {
    const DWORD required = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (!required) return path;
    std::vector<wchar_t> buffer(static_cast<std::size_t>(required));
    const DWORD written = GetFullPathNameW(path.c_str(), required, buffer.data(), nullptr);
    if (!written || written >= required) return path;
    return std::wstring(buffer.data(), written);
}

std::wstring ReadableName(std::wstring name) {
    // A subject may contain line breaks; keep each metadata record on one line.
    for (wchar_t& character : name) {
        if (character < L' ' || character == 0x7F) character = L' ';
    }
    return name.empty() ? L"неизвестно" : name;
}

std::wstring CertificateSubject(PCCERT_CONTEXT context) {
    const DWORD required = CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                             0, nullptr, nullptr, 0);
    if (required <= 1) return L"неизвестно";
    std::vector<wchar_t> buffer(static_cast<std::size_t>(required));
    const DWORD written = CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                            0, nullptr, buffer.data(), required);
    if (written <= 1 || written > required) return L"неизвестно";
    return ReadableName(std::wstring(buffer.data()));
}

std::wstring CrlIssuer(PCCRL_CONTEXT context) {
    if (!context || !context->pCrlInfo) return L"неизвестно";
    CERT_NAME_BLOB issuer = context->pCrlInfo->Issuer;
    const DWORD required = CertNameToStrW(X509_ASN_ENCODING, &issuer,
                                         CERT_X500_NAME_STR, nullptr, 0);
    if (required <= 1) return L"неизвестно";
    std::vector<wchar_t> buffer(static_cast<std::size_t>(required));
    const DWORD written = CertNameToStrW(X509_ASN_ENCODING, &issuer,
                                        CERT_X500_NAME_STR, buffer.data(), required);
    if (written <= 1 || written > required) return L"неизвестно";
    return ReadableName(std::wstring(buffer.data()));
}

template <typename Context, typename PropertyGetter>
std::wstring Sha1Thumbprint(const Context* context, PropertyGetter getProperty) {
    BYTE hash[20] = {};
    DWORD size = sizeof(hash);
    if (!getProperty(context, CERT_SHA1_HASH_PROP_ID, hash, &size) || size != sizeof(hash)) {
        return L"неизвестно";
    }
    const wchar_t digits[] = L"0123456789ABCDEF";
    std::wstring thumbprint;
    thumbprint.reserve(sizeof(hash) * 2);
    for (BYTE value : hash) {
        thumbprint += digits[value >> 4];
        thumbprint += digits[value & 0x0F];
    }
    return thumbprint;
}

std::wstring ObjectMetadata(DWORD kind, const void* context) {
    // Metadata is diagnostic only. Failure to read it must not prevent import
    // or change the counters for an otherwise valid object.
    try {
        if (kind == CERT_QUERY_CONTENT_CERT && context) {
            const PCCERT_CONTEXT certificate = static_cast<PCCERT_CONTEXT>(context);
            return L"Subject: " + CertificateSubject(certificate) + L"; SHA-1: " +
                   Sha1Thumbprint(certificate, CertGetCertificateContextProperty);
        }
        if (kind == CERT_QUERY_CONTENT_CRL && context) {
            const PCCRL_CONTEXT crl = static_cast<PCCRL_CONTEXT>(context);
            return L"Издатель CRL: " + CrlIssuer(crl) + L"; SHA-1: " +
                   Sha1Thumbprint(crl, CertGetCRLContextProperty);
        }
    } catch (const std::exception&) {
        // Keep the actual import path independent of diagnostic allocation or
        // name formatting errors; the fallback still identifies the object.
    }
    return kind == CERT_QUERY_CONTENT_CRL
        ? L"Издатель CRL: неизвестно; SHA-1: неизвестно"
        : L"Subject: неизвестно; SHA-1: неизвестно";
}

std::wstring StoreLabel(const std::wstring& store) {
    if (store == L"Root") return L"Доверенные корневые центры сертификации (Root)";
    if (store == L"CA") return L"Промежуточные центры сертификации (CA)";
    return L"Личное (My)";
}

std::wstring LocationLabel(Location location) {
    return location == Location::CurrentUser ? L"Текущий пользователь" : L"Локальный компьютер";
}

bool IsCertificateAuthority(const CERT_INFO& info) {
    const LPCSTR oids[] = { szOID_BASIC_CONSTRAINTS2, szOID_BASIC_CONSTRAINTS };
    for (std::size_t oidIndex = 0; oidIndex < 2; ++oidIndex) {
        const CERT_EXTENSION* extension = CertFindExtension(
            oids[oidIndex], info.cExtension, info.rgExtension);
        if (!extension) continue;
        void* decoded = nullptr;
        DWORD decodedSize = 0;
        const BOOL succeeded = CryptDecodeObjectEx(
            X509_ASN_ENCODING, oids[oidIndex], extension->Value.pbData,
            extension->Value.cbData, CRYPT_DECODE_ALLOC_FLAG, nullptr,
            &decoded, &decodedSize);
        const DWORD error = succeeded ? ERROR_SUCCESS : GetLastError();
        LocalMemory decodedMemory(decoded);
        if (!succeeded) throw WindowsFailure(L"Не удалось разобрать Basic Constraints", error);
        if (oidIndex == 0) {
            if (!decoded || decodedSize < sizeof(CERT_BASIC_CONSTRAINTS2_INFO)) {
                throw WindowsFailure(L"Некорректное расширение Basic Constraints", ERROR_INVALID_DATA);
            }
            return static_cast<const CERT_BASIC_CONSTRAINTS2_INFO*>(decoded)->fCA != FALSE;
        }
        if (!decoded || decodedSize < sizeof(CERT_BASIC_CONSTRAINTS_INFO)) {
            throw WindowsFailure(L"Некорректное расширение Basic Constraints", ERROR_INVALID_DATA);
        }
        const CERT_BASIC_CONSTRAINTS_INFO* constraints =
            static_cast<const CERT_BASIC_CONSTRAINTS_INFO*>(decoded);
        return constraints->SubjectType.cbData && constraints->SubjectType.pbData &&
               (constraints->SubjectType.pbData[0] & CERT_CA_SUBJECT_FLAG) != 0;
    }
    return false;
}

HCERTSTORE OpenSystemStore(const std::wstring& store, Location location) {
    const DWORD scope = location == Location::CurrentUser
        ? CERT_SYSTEM_STORE_CURRENT_USER : CERT_SYSTEM_STORE_LOCAL_MACHINE;
    return CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, scope, store.c_str());
}

bool HasKeyAssociation(PCCERT_CONTEXT certificate) {
    DWORD size = 0;
    return CertGetCertificateContextProperty(certificate, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &size) ||
           CertGetCertificateContextProperty(certificate, CERT_KEY_CONTEXT_PROP_ID, nullptr, &size);
}

bool AddObject(HCERTSTORE store, DWORD kind, const void* context, bool fromPfx) {
    // A plain duplicate remains a skip. A PFX containing a key must merge its
    // provider association into an already installed public certificate.
    const bool mergeKey = fromPfx && kind == CERT_QUERY_CONTENT_CERT &&
        HasKeyAssociation(static_cast<PCCERT_CONTEXT>(context));
    const BOOL succeeded = kind == CERT_QUERY_CONTENT_CERT
        ? CertAddCertificateContextToStore(store, static_cast<PCCERT_CONTEXT>(context),
                                          mergeKey ? CERT_STORE_ADD_USE_EXISTING : CERT_STORE_ADD_NEW, nullptr)
        : CertAddCRLContextToStore(store, static_cast<PCCRL_CONTEXT>(context),
                                  CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES, nullptr);
    if (succeeded) return true;
    const DWORD error = GetLastError();
    if (error == static_cast<DWORD>(CRYPT_E_EXISTS)) return false;
    throw WindowsFailure(L"Ошибка установки", error);
}

void ReadFileBytes(const std::wstring& path, FileBytes& bytes) {
    FileHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (file.get() == INVALID_HANDLE_VALUE) throw WindowsFailure(L"Не удалось открыть файл", GetLastError());
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file.get(), &size)) throw WindowsFailure(L"Не удалось определить размер файла", GetLastError());
    if (size.QuadPart < 0 || static_cast<ULONGLONG>(size.QuadPart) > MAXDWORD) {
        throw BackendError(L"Файл слишком большой для Windows CryptoAPI");
    }
    bytes.value.resize(static_cast<std::size_t>(size.QuadPart));
    std::size_t offset = 0;
    while (offset < bytes.value.size()) {
        DWORD read = 0;
        const DWORD wanted = static_cast<DWORD>((std::min)(bytes.value.size() - offset,
                                                          static_cast<std::size_t>(1024 * 1024)));
        if (!ReadFile(file.get(), bytes.value.data() + offset, wanted, &read, nullptr)) {
            throw WindowsFailure(L"Не удалось прочитать файл", GetLastError());
        }
        if (!read) throw WindowsFailure(L"Файл изменился во время чтения", ERROR_HANDLE_EOF);
        offset += read;
    }
}

HCERTSTORE QueryStore(const std::vector<BYTE>& bytes, DWORD content, DWORD format) {
    CRYPT_DATA_BLOB blob = {static_cast<DWORD>(bytes.size()), const_cast<BYTE*>(bytes.data())};
    HCERTSTORE rawStore = nullptr;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob, content, format, 0,
                          nullptr, nullptr, nullptr, &rawStore, nullptr, nullptr)) {
        const DWORD error = GetLastError();
        if (rawStore) CertCloseStore(rawStore, 0);
        throw WindowsFailure(L"Не удалось прочитать сертификат/CRL/PKCS#7/SST", error);
    }
    if (!rawStore) throw BackendError(L"Файл не содержит доступного хранилища сертификатов/CRL");
    return rawStore;
}

HCERTSTORE ImportPfx(CRYPT_DATA_BLOB& blob, const std::wstring& path,
                     const Options& options, const PfxImporter& importer) {
    const DWORD flags = (options.location == Location::CurrentUser ? CRYPT_USER_KEYSET : CRYPT_MACHINE_KEYSET) |
                         PKCS12_INCLUDE_EXTENDED_PROPERTIES |
                         (options.dryRun ? PKCS12_NO_PERSIST_KEY : 0);
    const auto import = [&](LPCWSTR password) -> HCERTSTORE {
        HCERTSTORE store = importer ? importer(&blob, password, flags) : PFXImportCertStore(&blob, password, flags);
        if (!store) throw WindowsFailure(L"Не удалось импортировать PFX/P12", GetLastError());
        return store;
    };
    // Verification imports no key material. Do not persist keys for failed
    // password attempts or request a password for an unprotected PFX.
    if (PFXVerifyPassword(&blob, L"", 0)) return import(L"");
    if (PFXVerifyPassword(&blob, nullptr, 0)) return import(nullptr);
    if (!options.passwordPrompt) throw BackendError(L"Для PFX/P12 требуется пароль; запрос пароля недоступен");
    bool retry = false;
    for (;;) {
        PasswordBuffer password;
        bool accepted = false;
        try {
            accepted = options.passwordPrompt(path, retry, password.value);
        } catch (...) {
            // An external prompt may include sensitive text in its exception.
            // Never put that exception message into the import log.
            throw BackendError(L"Ошибка диалога ввода пароля PFX/P12");
        }
        if (!accepted) throw PasswordCancelled();
        if (PFXVerifyPassword(&blob, password.value.c_str(), 0)) return import(password.value.c_str());
        // A malformed/unsupported PFX can also fail password verification.
        // The dialog offers retry or cancel without logging the secret.
        retry = true;
    }
}

std::string TrimPemLine(std::string line) {
    const std::string::size_type first = line.find_first_not_of(" \t\r");
    if (first == std::string::npos) return std::string();
    const std::string::size_type last = line.find_last_not_of(" \t\r");
    return line.substr(first, last - first + 1);
}

bool HasPemEnvelope(const std::vector<BYTE>& bytes) {
    if (std::find(bytes.begin(), bytes.end(), static_cast<BYTE>(0)) != bytes.end()) return false;
    bool beginning = true;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const BYTE character = bytes[index];
        if (character == '\n') { beginning = true; continue; }
        if (beginning && (character == ' ' || character == '\t' || character == '\r')) continue;
        if (beginning && index + 3 <= bytes.size() && character == 0xEF &&
            bytes[index + 1] == 0xBB && bytes[index + 2] == 0xBF) { index += 2; continue; }
        if (beginning && ((index + 10 <= bytes.size() &&
            !std::memcmp(bytes.data() + index, "-----BEGIN", 10)) ||
            (index + 8 <= bytes.size() && !std::memcmp(bytes.data() + index, "-----END", 8)))) return true;
        beginning = false;
    }
    return false;
}

bool PemMarker(const std::string& line, const char* prefix, std::string& label) {
    const std::string start = std::string("-----") + prefix + " ";
    if (line.compare(0, start.size(), start) || line.size() < start.size() + 6 ||
        line.compare(line.size() - 5, 5, "-----")) return false;
    label = line.substr(start.size(), line.size() - start.size() - 5);
    return !label.empty() && label.find('-') == std::string::npos;
}

DWORD PemContent(const std::string& label) {
    if (label == "CERTIFICATE" || label == "X509 CERTIFICATE") return CERT_QUERY_CONTENT_FLAG_CERT;
    if (label == "X509 CRL" || label == "CRL") return CERT_QUERY_CONTENT_FLAG_CRL;
    if (label == "PKCS7" || label == "PKCS #7 SIGNED DATA") return CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED;
    return 0;
}

std::vector<BYTE> DecodePemPayload(const std::string& payload) {
    if (payload.empty() || payload.size() > MAXDWORD) throw BackendError(L"Пустой или слишком большой PEM-блок");
    for (char character : payload) {
        const bool alphabet = (character >= 'A' && character <= 'Z') ||
            (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
            character == '+' || character == '/' || character == '=';
        if (!alphabet) throw BackendError(L"Некорректные данные Base64 в PEM-блоке");
    }
    DWORD size = 0;
    const DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT;
    if (!CryptStringToBinaryA(payload.data(), static_cast<DWORD>(payload.size()), flags,
                              nullptr, &size, nullptr, nullptr)) {
        throw WindowsFailure(L"Не удалось декодировать PEM-блок", GetLastError());
    }
    std::vector<BYTE> decoded(size);
    if (!CryptStringToBinaryA(payload.data(), static_cast<DWORD>(payload.size()), flags,
                              decoded.data(), &size, nullptr, nullptr)) {
        throw WindowsFailure(L"Не удалось декодировать PEM-блок", GetLastError());
    }
    decoded.resize(size);
    return decoded;
}

template <typename Consumer, typename Reporter>
void ReadPemBlocks(const std::vector<BYTE>& bytes, const Consumer& consume, const Reporter& report) {
    std::string label;
    std::string payload;
    bool active = false;
    std::size_t block = 0;
    const auto issue = [&](const std::wstring& text) {
        report(L"PEM-блок #" + std::to_wstring(block) + L": " + text);
    };
    std::size_t offset = 0;
    if (bytes.size() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) offset = 3;
    while (offset < bytes.size()) {
        const std::size_t start = offset;
        while (offset < bytes.size() && bytes[offset] != '\n') ++offset;
        std::string line(reinterpret_cast<const char*>(bytes.data() + start), offset - start);
        if (offset < bytes.size()) ++offset;
        line = TrimPemLine(std::move(line));
        if (line.compare(0, 10, "-----BEGIN") == 0) {
            if (active) issue(L"отсутствует закрывающая строка END");
            ++block;
            payload.clear();
            active = PemMarker(line, "BEGIN", label);
            if (!active) issue(L"некорректная строка BEGIN");
            continue;
        }
        if (line.compare(0, 8, "-----END") == 0) {
            std::string ending;
            if (!active) { ++block; issue(L"строка END без соответствующей BEGIN"); continue; }
            active = false;
            if (!PemMarker(line, "END", ending) || ending != label) {
                issue(L"строка END не соответствует BEGIN");
                continue;
            }
            try {
                const DWORD content = PemContent(label);
                if (!content) throw BackendError(L"неподдерживаемый тип PEM-блока (закрытые ключи PEM не импортируются)");
                consume(DecodePemPayload(payload), content);
            } catch (const std::exception& error) {
                issue(ExceptionMessage(error));
            }
            payload.clear();
            continue;
        }
        if (active) {
            for (char character : line) {
                if (character != ' ' && character != '\t' && character != '\r') payload += character;
            }
        }
    }
    if (active) issue(L"отсутствует закрывающая строка END");
}

template <typename Context, typename Enumerator, typename Consumer>
void EnumerateObjects(HCERTSTORE store, DWORD kind, Enumerator enumerate,
                      typename ContextHandle<Context>::Releaser freeContext,
                      const Consumer& consume) {
    ContextHandle<Context> current(freeContext);
    for (;;) {
        // The enumeration API owns and frees the previous context, including
        // on failure. Release it before the call so it cannot be freed twice.
        const Context* next = enumerate(store, current.release());
        const DWORD error = next ? ERROR_SUCCESS : GetLastError();
        current.reset(next);
        if (!next) {
            if (error != static_cast<DWORD>(CRYPT_E_NOT_FOUND) && error != ERROR_NO_MORE_FILES) {
                throw WindowsFailure(L"Не удалось перечислить содержимое файла", error);
            }
            return;
        }
        consume(kind, static_cast<const void*>(current.get()));
    }
}

}  // namespace

std::wstring FormatWindowsError(DWORD error) {
    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    LocalMemory allocatedMessage(buffer);
    std::wstring message = length && buffer ? std::wstring(buffer, length) : L"Ошибка Windows";
    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' ||
                               message.back() == L' ' || message.back() == L'\t')) {
        message.pop_back();
    }
    const wchar_t digits[] = L"0123456789ABCDEF";
    std::wstring code = L"0x";
    for (int shift = 28; shift >= 0; shift -= 4) code += digits[(error >> shift) & 0x0F];
    return message + L" (" + code + L")";
}

bool IsAdministrator() {
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;
    if (!AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &administrators)) return false;
    BOOL member = FALSE;
    const BOOL checked = CheckTokenMembership(nullptr, administrators, &member);
    FreeSid(administrators);
    return checked != FALSE && member != FALSE;
}

std::wstring SelectStore(DWORD kind, const void* context, StoreMode mode) {
    if (mode == StoreMode::Root) return L"Root";
    if (kind == CERT_QUERY_CONTENT_CRL) return L"CA";
    if (kind != CERT_QUERY_CONTENT_CERT || !context) {
        throw WindowsFailure(L"Некорректный тип объекта сертификата", ERROR_INVALID_PARAMETER);
    }
    const CERT_CONTEXT* certificate = static_cast<PCCERT_CONTEXT>(context);
    if (!certificate->pCertInfo) {
        throw WindowsFailure(L"Нет сведений о сертификате", ERROR_INVALID_DATA);
    }
    const CERT_INFO& info = *certificate->pCertInfo;
    if (!IsCertificateAuthority(info)) return L"My";
    // The legacy comparison API takes mutable blob pointers but only reads
    // their contents. Copies preserve the const contract of SelectStore.
    CERT_NAME_BLOB subject = info.Subject;
    CERT_NAME_BLOB issuer = info.Issuer;
    if (CertCompareCertificateName(X509_ASN_ENCODING, &subject, &issuer)) {
        if (CryptVerifyCertificateSignatureEx(0, X509_ASN_ENCODING,
                                             CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,
                                             const_cast<CERT_CONTEXT*>(certificate),
                                             CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
                                             const_cast<CERT_CONTEXT*>(certificate), 0, nullptr)) {
            return L"Root";
        }
        const DWORD error = GetLastError();
        // Self-issued CA certificates can use another key during rollover.
        // An unavailable algorithm/provider must remain an explicit error.
        if (error != static_cast<DWORD>(NTE_BAD_SIGNATURE) && error != kInvalidSignature) {
            throw WindowsFailure(L"Не удалось проверить собственную подпись CA", error);
        }
    }
    return L"CA";
}

Summary ImportFiles(const std::vector<std::wstring>& paths, const Options& options,
                    const LogSink& log, const StoreOpener& opener, const PfxImporter& pfxImporter) {
    Summary summary;
    for (const std::wstring& path : paths) {
        try {
            Emit(log, L"Файл: " + FullPathForLog(path));
            FileBytes bytes;
            ReadFileBytes(path, bytes);
            std::size_t count = 0;
            std::size_t blockErrors = 0;
            const auto process = [&](DWORD kind, const void* context, bool fromPfx) {
                ++count;
                const std::wstring label = FileName(path) + L" [" +
                    (kind == CERT_QUERY_CONTENT_CRL ? L"CRL" : L"сертификат") +
                    L" #" + std::to_wstring(count) + L"]";
                Emit(log, L"  " + label + L": " + ObjectMetadata(kind, context));
                try {
                    const std::wstring store = SelectStore(kind, context, options.mode);
                    const std::wstring target = LocationLabel(options.location) + L" / " + StoreLabel(store);
                    if (options.dryRun) {
                        ++summary.planned;
                        Emit(log, L"[ПЛАН] " + label + L" -> " + target);
                        return;
                    }
                    const HCERTSTORE destination = opener ? opener(store, options.location)
                                                         : OpenSystemStore(store, options.location);
                    const DWORD openError = destination ? ERROR_SUCCESS : GetLastError();
                    StoreHandle destinationStore(destination);
                    if (!destination) throw WindowsFailure(L"Не удалось открыть " + store, openError);
                    if (AddObject(destinationStore.get(), kind, context, fromPfx)) {
                        ++summary.installed;
                        const bool hasKey = fromPfx && kind == CERT_QUERY_CONTENT_CERT &&
                            HasKeyAssociation(static_cast<PCCERT_CONTEXT>(context));
                        Emit(log, L"[OK] " + label + L" -> " + target +
                                  (hasKey ? L" (сертификат и связь с закрытым ключом добавлены/обновлены)" : L""));
                    } else {
                        ++summary.skipped;
                        Emit(log, L"[ЕСТЬ] " + label + L" -> " + target +
                                  L" (уже есть; для CRL — такой же или новее)");
                    }
                } catch (const std::exception& exception) {
                    ++summary.errors;
                    Emit(log, L"[ОШИБКА] " + label + L": " + ExceptionMessage(exception));
                }
            };
            const auto enumerate = [&](HCERTSTORE store, bool fromPfx) {
                const std::size_t before = count;
                const auto consume = [&](DWORD kind, const void* context) { process(kind, context, fromPfx); };
                EnumerateObjects<CERT_CONTEXT>(store, CERT_QUERY_CONTENT_CERT,
                                               CertEnumCertificatesInStore, CertFreeCertificateContext, consume);
                EnumerateObjects<CRL_CONTEXT>(store, CERT_QUERY_CONTENT_CRL,
                                              CertEnumCRLsInStore, CertFreeCRLContext, consume);
                if (count == before) throw BackendError(L"В контейнере нет сертификатов или CRL");
            };
            CRYPT_DATA_BLOB blob = {static_cast<DWORD>(bytes.value.size()), bytes.value.data()};
            if (PFXIsPFXBlob(&blob)) {
                StoreHandle pfxStore(ImportPfx(blob, path, options, pfxImporter));
                enumerate(pfxStore.get(), true);
            } else {
                // Identify DER/SST before looking for textual PEM markers: a
                // binary subject or serialized property may contain BEGIN text.
                HCERTSTORE rawBinary = nullptr;
                const BOOL binary = CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob, kExpectedContent,
                                                      CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                                                      nullptr, nullptr, nullptr, &rawBinary, nullptr, nullptr);
                StoreHandle binaryStore(rawBinary);
                if (binary && rawBinary) {
                    enumerate(binaryStore.get(), false);
                } else if (HasPemEnvelope(bytes.value)) {
                    const auto block = [&](const std::vector<BYTE>& encoded, DWORD content) {
                        StoreHandle store(QueryStore(encoded, content, CERT_QUERY_FORMAT_FLAG_BINARY));
                        enumerate(store.get(), false);
                    };
                    const auto error = [&](const std::wstring& message) {
                        ++summary.errors;
                        ++blockErrors;
                        Emit(log, L"[ОШИБКА] " + FileName(path) + L": " + message);
                    };
                    ReadPemBlocks(bytes.value, block, error);
                } else {
                    StoreHandle store(QueryStore(bytes.value, kExpectedContent, kExpectedFormat));
                    enumerate(store.get(), false);
                }
            }
            if (!count && !blockErrors) throw BackendError(L"В файле нет сертификатов или CRL");
        } catch (const PasswordCancelled&) {
            ++summary.cancelled;
            Emit(log, L"[ОТМЕНА] " + FileName(path) + L": ввод пароля отменён, файл пропущен.");
        } catch (const std::exception& exception) {
            ++summary.errors;
            Emit(log, L"[ОШИБКА] " + FileName(path) + L": " + ExceptionMessage(exception));
        }
    }
    Emit(log, L"Итог: объектов установлено " + std::to_wstring(summary.installed) +
              L", уже есть " + std::to_wstring(summary.skipped) +
              L", ошибок " + std::to_wstring(summary.errors) +
              L", только проверено " + std::to_wstring(summary.planned) +
              L", отменено файлов " + std::to_wstring(summary.cancelled) + L".");
    return summary;
}

}  // namespace certinstaller
