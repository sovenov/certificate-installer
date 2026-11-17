// Native regression tests. Every ImportFiles call supplies a memory-only opener.
// The test executable never opens or writes a Windows system certificate store.
#include "certificate_import.h"
#include "test_fixtures.h"
#include "extended_test_fixtures.h"
#include <ncrypt.h>

#include <algorithm>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

namespace {
using namespace certinstaller;
using Bytes = std::vector<BYTE>;
using StoreKey = std::pair<std::wstring, Location>;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

Bytes Decode(const char* text) {
    DWORD size = 0;
    Require(CryptStringToBinaryA(text, 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr) != FALSE,
            "Cannot measure embedded Base64 fixture");
    Bytes bytes(size);
    Require(CryptStringToBinaryA(text, 0, CRYPT_STRING_BASE64, bytes.data(), &size, nullptr, nullptr) != FALSE,
            "Cannot decode embedded Base64 fixture");
    bytes.resize(size);
    return bytes;
}

Bytes DerTlv(BYTE tag, const Bytes& value) {
    Bytes result(1, tag);
    if (value.size() < 128) {
        result.push_back(static_cast<BYTE>(value.size()));
    } else {
        Bytes length;
        for (size_t size = value.size(); size; size >>= 8)
            length.insert(length.begin(), static_cast<BYTE>(size & 0xff));
        result.push_back(static_cast<BYTE>(0x80 | length.size()));
        result.insert(result.end(), length.begin(), length.end());
    }
    result.insert(result.end(), value.begin(), value.end());
    return result;
}

void Append(Bytes& target, const Bytes& value) {
    target.insert(target.end(), value.begin(), value.end());
}

Bytes Pkcs7(std::vector<Bytes> certs, std::vector<Bytes> crls) {
    // Degenerate SignedData: no signer, no payload; public cert/CRL container.
    const Bytes signedDataOid{0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02};
    const Bytes dataOid{0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x01};
    Bytes content{0x02,0x01,0x01,0x31,0x00};  // version 1, empty digestAlgorithms.
    Append(content, DerTlv(0x30, dataOid));
    for (auto* collection : {&certs, &crls}) {
        if (collection->empty()) continue;
        std::sort(collection->begin(), collection->end());
        Bytes encoded;
        for (const auto& item : *collection) Append(encoded, item);
        Append(content, DerTlv(collection == &certs ? 0xa0 : 0xa1, encoded));
    }
    Append(content, Bytes{0x31,0x00});  // Empty signerInfos.
    Bytes wrapper = signedDataOid;
    Append(wrapper, DerTlv(0xa0, DerTlv(0x30, content)));
    return DerTlv(0x30, wrapper);
}

Bytes Chain(const char* crl = testfixtures::CRL_OLD) {
    return Pkcs7({Decode(testfixtures::ROOT), Decode(testfixtures::INTERMEDIATE),
                  Decode(testfixtures::LEAF)}, {Decode(crl)});
}

Bytes Base64(const Bytes& binary, const char* label = nullptr) {
    DWORD size = 0;
    const DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
    Require(CryptBinaryToStringA(binary.data(), static_cast<DWORD>(binary.size()), flags, nullptr, &size) != FALSE,
            "Cannot measure encoded fixture");
    std::string text(size, '\0');
    Require(CryptBinaryToStringA(binary.data(), static_cast<DWORD>(binary.size()), flags, &text[0], &size) != FALSE,
            "Cannot encode fixture");
    if (!text.empty() && text.back() == '\0') text.pop_back();
    std::string output;
    if (label) output = std::string("-----BEGIN ") + label + "-----\r\n";
    for (size_t offset = 0; offset < text.size(); offset += 64)
        output += text.substr(offset, 64) + "\r\n";
    if (label) output += std::string("-----END ") + label + "-----\r\n";
    return Bytes(output.begin(), output.end());
}

struct CertificateDeleter {
    void operator()(PCCERT_CONTEXT context) const { if (context) CertFreeCertificateContext(context); }
};
using Certificate = std::unique_ptr<const CERT_CONTEXT, CertificateDeleter>;

struct StoreDeleter {
    void operator()(void* store) const { if (store) CertCloseStore(store, 0); }
};
using TestStore = std::unique_ptr<void, StoreDeleter>;

Certificate ParseCertificate(const char* fixture) {
    Bytes bytes = Decode(fixture);
    Certificate certificate(CertCreateCertificateContext(X509_ASN_ENCODING, bytes.data(),
                                                         static_cast<DWORD>(bytes.size())));
    Require(certificate != nullptr, "Cannot parse public certificate fixture");
    return certificate;
}

class TempDirectory {
public:
    TempDirectory() {
        wchar_t temporary[MAX_PATH + 1]{};
        wchar_t unique[MAX_PATH + 1]{};
        const DWORD length = GetTempPathW(MAX_PATH, temporary);
        Require(length != 0 && length < MAX_PATH, "Cannot find temporary directory");
        Require(GetTempFileNameW(temporary, L"cit", 0, unique) != 0, "Cannot reserve temporary path");
        Require(DeleteFileW(unique) != FALSE, "Cannot release temporary reservation");
        Require(CreateDirectoryW(unique, nullptr) != FALSE, "Cannot create temporary directory");
        path_ = unique;
    }
    ~TempDirectory() {
        for (const auto& file : files_) DeleteFileW(file.c_str());
        if (!path_.empty()) RemoveDirectoryW(path_.c_str());
    }
    std::wstring Write(const std::wstring& name, const Bytes& bytes) {
        const std::wstring file = path_ + L"\\" + name;
        HANDLE handle = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
        Require(handle != INVALID_HANDLE_VALUE, "Cannot create temporary fixture");
        files_.push_back(file);
        DWORD written = 0;
        const BOOL success = WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
        CloseHandle(handle);
        Require(success != FALSE && written == bytes.size(), "Cannot write temporary fixture");
        return file;
    }
private:
    std::wstring path_;
    std::vector<std::wstring> files_;
};

class MemoryStores {
public:
    std::vector<StoreKey> requests;
    ~MemoryStores() {
        for (auto& store : stores_) if (store.second) CertCloseStore(store.second, 0);
    }
    HCERTSTORE Open(const std::wstring& name, Location location) {
        Require(name == L"Root" || name == L"CA" || name == L"My", "Unexpected logical store name");
        const StoreKey key(name, location);
        requests.push_back(key);
        auto found = stores_.find(key);
        if (found == stores_.end()) {
            // Every real CertOpenStore call in this suite uses MEMORY only.
            HCERTSTORE handle = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
            Require(handle != nullptr, "Cannot create memory store");
            found = stores_.emplace(key, handle).first;
        }
        HCERTSTORE duplicate = CertDuplicateStore(found->second);
        Require(duplicate != nullptr, "Cannot duplicate memory store handle");
        return duplicate;  // The importer owns and closes this reference.
    }
    StoreOpener Opener() {
        return [this](const std::wstring& name, Location location) { return Open(name, location); };
    }
    HCERTSTORE At(const std::wstring& name, Location location) const {
        auto found = stores_.find(StoreKey(name, location));
        Require(found != stores_.end(), "Expected memory store was not opened");
        return found->second;
    }
    size_t Size() const { return stores_.size(); }
    void CloseChecked() {
        for (auto& store : stores_) {
            HCERTSTORE handle = store.second;
            store.second = nullptr;  // CHECK_FLAG closes even when reporting leaked contexts.
            Require(CertCloseStore(handle, CERT_CLOSE_STORE_CHECK_FLAG) != FALSE,
                    "Importer retained a certificate or CRL context in memory store");
        }
        stores_.clear();
    }
private:
    std::map<StoreKey, HCERTSTORE> stores_;
};

std::vector<Bytes> Certificates(HCERTSTORE store) {
    std::vector<Bytes> result;
    PCCERT_CONTEXT previous = nullptr;
    while ((previous = CertEnumCertificatesInStore(store, previous)) != nullptr)
        result.emplace_back(previous->pbCertEncoded, previous->pbCertEncoded + previous->cbCertEncoded);
    const DWORD error = GetLastError();
    Require(error == CRYPT_E_NOT_FOUND || error == ERROR_NO_MORE_FILES, "Cannot enumerate memory certificates");
    std::sort(result.begin(), result.end());
    return result;
}

std::vector<Bytes> Crls(HCERTSTORE store) {
    std::vector<Bytes> result;
    PCCRL_CONTEXT previous = nullptr;
    while ((previous = CertEnumCRLsInStore(store, previous)) != nullptr)
        result.emplace_back(previous->pbCrlEncoded, previous->pbCrlEncoded + previous->cbCrlEncoded);
    const DWORD error = GetLastError();
    Require(error == CRYPT_E_NOT_FOUND || error == ERROR_NO_MORE_FILES, "Cannot enumerate memory CRLs");
    std::sort(result.begin(), result.end());
    return result;
}

Options Settings(Location location = Location::CurrentUser, StoreMode mode = StoreMode::Automatic,
                 bool dryRun = false) {
    Options options{};
    options.location = location;
    options.mode = mode;
    options.dryRun = dryRun;
    return options;
}

void ExpectSummary(const Summary& actual, size_t installed, size_t skipped, size_t errors,
                   size_t planned = 0, size_t cancelled = 0) {
    if (actual.installed == installed && actual.skipped == skipped && actual.errors == errors &&
        actual.planned == planned && actual.cancelled == cancelled) return;
    std::ostringstream message;
    message << "Unexpected summary: installed=" << actual.installed << ", skipped=" << actual.skipped
            << ", errors=" << actual.errors << ", planned=" << actual.planned << ", cancelled=" << actual.cancelled;
    throw std::runtime_error(message.str());
}

const LogSink QuietLog = [](const std::wstring&) {};

Bytes SerializedStore(bool markerProperty = false) {
    TestStore store(CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr));
    Require(store != nullptr, "Cannot create MEMORY source for SST");
    for (const char* fixture : {testfixtures::ROOT, testfixtures::INTERMEDIATE, testfixtures::LEAF}) {
        const Bytes encoded = Decode(fixture);
        PCCERT_CONTEXT added = nullptr;
        Require(CertAddEncodedCertificateToStore(store.get(), X509_ASN_ENCODING, encoded.data(),
                static_cast<DWORD>(encoded.size()), CERT_STORE_ADD_NEW, &added) != FALSE,
                "Cannot populate MEMORY SST source certificates");
        Certificate certificate(added);
        if (markerProperty) {
            // Serialized properties are arbitrary binary data, not PEM text.
            const char text[] = "\n-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n";
            CRYPT_DATA_BLOB marker = {sizeof(text), reinterpret_cast<BYTE*>(const_cast<char*>(text))};
            Require(CertSetCertificateContextProperty(certificate.get(), CERT_DESCRIPTION_PROP_ID, 0, &marker) != FALSE,
                    "Cannot set PEM-like property in MEMORY SST fixture");
        }
    }
    const Bytes crl = Decode(testfixtures::CRL_OLD);
    Require(CertAddEncodedCRLToStore(store.get(), X509_ASN_ENCODING, crl.data(),
            static_cast<DWORD>(crl.size()), CERT_STORE_ADD_NEW, nullptr) != FALSE,
            "Cannot populate MEMORY SST source CRL");
    CRYPT_DATA_BLOB serialized = {};
    Require(CertSaveStore(store.get(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                         CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &serialized, 0) != FALSE,
            "Cannot measure serialized SST fixture");
    Bytes bytes(serialized.cbData);
    serialized.pbData = bytes.data();
    Require(CertSaveStore(store.get(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                         CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &serialized, 0) != FALSE,
            "Cannot serialize MEMORY SST fixture");
    bytes.resize(serialized.cbData);
    return bytes;
}

const wchar_t kFakeKeyContainer[] = L"CertificateInstaller-MEMORY-fixture-no-persisted-key";

class EphemeralPfxProbe {
public:
    std::vector<DWORD> requestedFlags;
    size_t privateKeys = 0;
    bool addSyntheticProviderInfo = true;

    PfxImporter Importer() {
        return [this](CRYPT_DATA_BLOB* blob, LPCWSTR password, DWORD flags) -> HCERTSTORE {
            requestedFlags.push_back(flags);
            Require(!(flags & CRYPT_EXPORTABLE), "PFX key was made exportable");
            Require(!(flags & PKCS12_ALLOW_OVERWRITE_KEY), "PFX was allowed to overwrite an existing key");
            Require(static_cast<bool>(flags & CRYPT_USER_KEYSET) != static_cast<bool>(flags & CRYPT_MACHINE_KEYSET),
                    "PFX scope must select exactly one keyset");
            // Mandatory in EVERY native PFX test: no key is persisted, even
            // when exercising the production flags passed into this seam.
            TestStore source(PFXImportCertStore(blob, password, flags | PKCS12_NO_PERSIST_KEY));
            Require(source != nullptr, "Cannot import public PFX fixture with NO_PERSIST_KEY");
            Certificate current;
            for (;;) {
                current.reset(CertEnumCertificatesInStore(source.get(), current.release()));
                if (!current) break;
                DWORD propertySize = 0;
                if (!CertGetCertificateContextProperty(current.get(), CERT_KEY_CONTEXT_PROP_ID,
                                                       nullptr, &propertySize)) continue;
                HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
                DWORD keySpec = 0;
                BOOL callerMustFree = FALSE;
                const BOOL acquired = CryptAcquireCertificatePrivateKey(
                    current.get(), CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
                    nullptr, &key, &keySpec, &callerMustFree);
                if (acquired && callerMustFree) {
                    if (keySpec == CERT_NCRYPT_KEY_SPEC) NCryptFreeObject(key);
                    else CryptReleaseContext(static_cast<HCRYPTPROV>(key), 0);
                }
                Require(acquired != FALSE && key != 0, "Ephemeral PFX private key cannot be acquired");
                ++privateKeys;
                if (addSyntheticProviderInfo) {
                    // CertAddCertificateContextToStore intentionally does not
                    // copy ephemeral KEY_CONTEXT. Test the persistent-provider
                    // merge contract with inert metadata in MEMORY, never by
                    // creating a real key container on disk.
                    CRYPT_KEY_PROV_INFO provider = {};
                    provider.pwszContainerName = const_cast<wchar_t*>(kFakeKeyContainer);
                    provider.pwszProvName = const_cast<wchar_t*>(MS_ENH_RSA_AES_PROV_W);
                    provider.dwProvType = PROV_RSA_AES;
                    provider.dwFlags = flags & CRYPT_MACHINE_KEYSET;
                    provider.dwKeySpec = AT_KEYEXCHANGE;
                    Require(CertSetCertificateContextProperty(current.get(), CERT_KEY_PROV_INFO_PROP_ID,
                                                               0, &provider) != FALSE,
                            "Cannot set synthetic MEMORY key association");
                }
            }
            return source.release();
        };
    }
};

void ExpectProviderAssociation(HCERTSTORE store, Location location) {
    Certificate expected = ParseCertificate(extended_test_fixtures::PFX_LEAF);
    Certificate actual(CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
                                                 CERT_FIND_EXISTING, expected.get(), nullptr));
    Require(actual != nullptr, "PFX leaf is missing from destination MEMORY store");
    DWORD size = 0;
    Require(CertGetCertificateContextProperty(actual.get(), CERT_KEY_PROV_INFO_PROP_ID, nullptr, &size) != FALSE,
            "PFX did not merge provider association into public certificate");
    Bytes buffer(size);
    Require(CertGetCertificateContextProperty(actual.get(), CERT_KEY_PROV_INFO_PROP_ID,
                                               buffer.data(), &size) != FALSE,
            "Cannot read merged provider association");
    const CRYPT_KEY_PROV_INFO* provider = reinterpret_cast<const CRYPT_KEY_PROV_INFO*>(buffer.data());
    Require(provider->pwszContainerName && !wcscmp(provider->pwszContainerName, kFakeKeyContainer),
            "PFX provider container name was lost in merge");
    Require((provider->dwFlags & CRYPT_MACHINE_KEYSET) ==
                static_cast<DWORD>(location == Location::LocalMachine ? CRYPT_MACHINE_KEYSET : 0),
            "PFX provider association has the wrong scope");
}

void TestClassification() {
    struct Case { const char* fixture; const wchar_t* expected; };
    const Case cases[] = {{testfixtures::ROOT, L"Root"}, {testfixtures::INTERMEDIATE, L"CA"},
                          {testfixtures::LEAF, L"My"}, {testfixtures::SELF_SIGNED_LEAF, L"My"},
                          {testfixtures::SELF_ISSUED_CA, L"CA"}};
    for (const auto& item : cases) {
        Certificate certificate = ParseCertificate(item.fixture);
        Require(SelectStore(CERT_QUERY_CONTENT_CERT, certificate.get(), StoreMode::Automatic) == item.expected,
                "Automatic certificate classification is incorrect");
        Require(SelectStore(CERT_QUERY_CONTENT_CERT, certificate.get(), StoreMode::Root) == L"Root",
                "Explicit Root mode did not override certificate classification");
    }
    Bytes encoded = Decode(testfixtures::CRL_OLD);
    PCCRL_CONTEXT crl = CertCreateCRLContext(X509_ASN_ENCODING, encoded.data(), static_cast<DWORD>(encoded.size()));
    Require(crl != nullptr, "Cannot parse embedded CRL");
    const std::wstring automatic = SelectStore(CERT_QUERY_CONTENT_CRL, crl, StoreMode::Automatic);
    const std::wstring forced = SelectStore(CERT_QUERY_CONTENT_CRL, crl, StoreMode::Root);
    CertFreeCRLContext(crl);
    Require(automatic == L"CA" && forced == L"Root", "CRL classification is incorrect");
}

void TestBasicConstraintsPolicies() {
    Certificate root = ParseCertificate(testfixtures::ROOT);
    Certificate intermediate = ParseCertificate(testfixtures::INTERMEDIATE);
    CERT_INFO info = *root->pCertInfo;
    // Different issuer prevents signature verification of this synthetic info view.
    info.Issuer = intermediate->pCertInfo->Subject;
    CERT_CONTEXT context = *root;
    context.pCertInfo = &info;
    info.cExtension = 0;
    info.rgExtension = nullptr;
    Require(SelectStore(CERT_QUERY_CONTENT_CERT, &context, StoreMode::Automatic) == L"My",
            "Certificate without Basic Constraints must use the declared leaf policy");
    struct Case { const char* oid; Bytes der; const wchar_t* expected; };
    const Case cases[] = {
        {szOID_BASIC_CONSTRAINTS, {0x30,0x04,0x03,0x02,0x07,0x80}, L"CA"},
        {szOID_BASIC_CONSTRAINTS, {0x30,0x04,0x03,0x02,0x06,0x40}, L"My"},
        {szOID_BASIC_CONSTRAINTS2, {0x30,0x03,0x01,0x01,0xff}, L"CA"},
        {szOID_BASIC_CONSTRAINTS2, {0x30,0x00}, L"My"},
    };
    for (const auto& item : cases) {
        CERT_EXTENSION extension{};
        extension.pszObjId = const_cast<char*>(item.oid);
        extension.Value.cbData = static_cast<DWORD>(item.der.size());
        extension.Value.pbData = const_cast<BYTE*>(item.der.data());
        info.cExtension = 1;
        info.rgExtension = &extension;
        Require(SelectStore(CERT_QUERY_CONTENT_CERT, &context, StoreMode::Automatic) == item.expected,
                "Legacy or modern Basic Constraints classification is incorrect");
    }
}

void TestSingleCertificateDerPemDuplicates() {
    TempDirectory files;
    MemoryStores stores;
    std::vector<std::wstring> paths;
    const char* fixtures[] = {testfixtures::ROOT, testfixtures::INTERMEDIATE, testfixtures::LEAF,
                              testfixtures::SELF_SIGNED_LEAF, testfixtures::SELF_ISSUED_CA};
    for (size_t index = 0; index != 5; ++index) {
        const std::wstring number = std::to_wstring(index);
        const Bytes encoded = Decode(fixtures[index]);
        paths.push_back(files.Write(number + L".crt", encoded));
        paths.push_back(files.Write(number + L"_pem.CRT", Base64(encoded, "CERTIFICATE")));
    }
    ExpectSummary(ImportFiles(paths, Settings(), QuietLog, stores.Opener()), 5, 5, 0);
    Require(Certificates(stores.At(L"Root", Location::CurrentUser)).size() == 1, "Expected one root CA");
    Require(Certificates(stores.At(L"CA", Location::CurrentUser)).size() == 2, "Expected two intermediate CAs");
    Require(Certificates(stores.At(L"My", Location::CurrentUser)).size() == 2, "Expected two leaf certificates");
    stores.CloseChecked();
}

void TestCerDerPemAndMixedCaseExtensions() {
    TempDirectory files;
    const Bytes root = Decode(testfixtures::ROOT);
    const Bytes intermediate = Decode(testfixtures::INTERMEDIATE);
    const Bytes leaf = Decode(testfixtures::LEAF);
    const std::vector<std::wstring> paths{
        files.Write(L"root.CeR", root),
        files.Write(L"intermediate_pem.cEr", Base64(intermediate, "CERTIFICATE")),
        files.Write(L"leaf.cer", leaf),
        files.Write(L"leaf_duplicate_pem.CER", Base64(leaf, "CERTIFICATE")),
    };
    for (Location location : {Location::CurrentUser, Location::LocalMachine}) {
        MemoryStores stores;
        ExpectSummary(ImportFiles(paths, Settings(location), QuietLog, stores.Opener()), 3, 1, 0);
        Require(stores.requests.size() == paths.size(), "Every CER file must reach the memory opener");
        for (const auto& request : stores.requests)
            Require(request.second == location, "CER import lost the selected scope");
        Require(Certificates(stores.At(L"Root", location)) == std::vector<Bytes>{root},
                "Mixed-case DER CER did not preserve the root certificate");
        Require(Certificates(stores.At(L"CA", location)) == std::vector<Bytes>{intermediate},
                "Mixed-case PEM CER did not preserve the intermediate certificate");
        Require(Certificates(stores.At(L"My", location)) == std::vector<Bytes>{leaf},
                "DER/PEM CER import lost or duplicated the leaf certificate");
        stores.CloseChecked();
    }
}

void TestPkcs7DerPemBase64AndDuplicates() {
    TempDirectory files;
    MemoryStores stores;
    const Bytes chain = Chain();
    const std::vector<std::wstring> paths{
        files.Write(L"\u0446\u0435\u043f\u043e\u0447\u043a\u0430_der.p7b", chain),
        files.Write(L"chain_pem.P7B", Base64(chain, "PKCS7")),
        files.Write(L"chain_base64.p7b", Base64(chain)),
        files.Write(L"root.crt", Decode(testfixtures::ROOT)),
    };
    ExpectSummary(ImportFiles(paths, Settings(), QuietLog, stores.Opener()), 4, 9, 0);
    Require(Certificates(stores.At(L"Root", Location::CurrentUser)) ==
            std::vector<Bytes>{Decode(testfixtures::ROOT)}, "PKCS7 root bytes differ");
    Require(Certificates(stores.At(L"CA", Location::CurrentUser)) ==
            std::vector<Bytes>{Decode(testfixtures::INTERMEDIATE)}, "PKCS7 intermediate bytes differ");
    Require(Certificates(stores.At(L"My", Location::CurrentUser)) ==
            std::vector<Bytes>{Decode(testfixtures::LEAF)}, "PKCS7 leaf bytes differ");
    Require(Crls(stores.At(L"CA", Location::CurrentUser)) ==
            std::vector<Bytes>{Decode(testfixtures::CRL_OLD)}, "PKCS7 CRL bytes differ");
    stores.CloseChecked();
}

void TestAllScopesAndStoreModes() {
    TempDirectory files;
    const std::wstring path = files.Write(L"chain.p7b", Chain());
    for (Location location : {Location::CurrentUser, Location::LocalMachine}) {
        for (StoreMode mode : {StoreMode::Automatic, StoreMode::Root}) {
            MemoryStores stores;
            ExpectSummary(ImportFiles({path}, Settings(location, mode), QuietLog, stores.Opener()), 4, 0, 0);
            Require(stores.requests.size() == 4, "All four objects must use the selected opener");
            for (const auto& request : stores.requests) {
                Require(request.second == location, "Selected scope was not applied to every object");
                if (mode == StoreMode::Root) Require(request.first == L"Root", "Root mode was not applied to every object");
            }
            if (mode == StoreMode::Root) {
                Require(stores.Size() == 1, "Forced Root must use one store");
                Require(Certificates(stores.At(L"Root", location)).size() == 3, "Forced Root lost certificates");
                Require(Crls(stores.At(L"Root", location)).size() == 1, "Forced Root lost CRL");
            } else {
                Require(stores.Size() == 3, "Automatic routing must populate Root, CA and My");
            }
            stores.CloseChecked();
        }
    }
}

void TestCrlNewerReplacesAndOlderDoesNotOverwrite() {
    TempDirectory files;
    MemoryStores stores;
    const std::wstring old = files.Write(L"old.crl", Decode(testfixtures::CRL_OLD));
    const std::wstring oldPem = files.Write(L"old_pem.crl", Base64(Decode(testfixtures::CRL_OLD), "X509 CRL"));
    const std::wstring newer = files.Write(L"newer.p7b", Pkcs7({}, {Decode(testfixtures::CRL_NEW)}));
    ExpectSummary(ImportFiles({old, oldPem, newer, old}, Settings(), QuietLog, stores.Opener()), 2, 2, 0);
    Require(Crls(stores.At(L"CA", Location::CurrentUser)) == std::vector<Bytes>{Decode(testfixtures::CRL_NEW)},
            "Older or identical CRL replaced the newer CRL");
    stores.CloseChecked();
}

void TestCertOnlyAndCrlOnlyPkcs7() {
    TempDirectory files;
    MemoryStores stores;
    const auto certs = files.Write(L"certs.p7b", Pkcs7({Decode(testfixtures::ROOT), Decode(testfixtures::INTERMEDIATE),
                                                      Decode(testfixtures::LEAF)}, {}));
    const auto crls = files.Write(L"crls.p7b", Pkcs7({}, {Decode(testfixtures::CRL_OLD)}));
    ExpectSummary(ImportFiles({certs, crls}, Settings(), QuietLog, stores.Opener()), 4, 0, 0);
    Require(stores.Size() == 3, "Cert-only and CRL-only PKCS7 routing failed");
    Require(Crls(stores.At(L"CA", Location::CurrentUser)).size() == 1, "CRL-only PKCS7 was ignored");
    stores.CloseChecked();
}

void TestCorruptAndEmptyFilesContinue() {
    TempDirectory files;
    MemoryStores stores;
    const auto corrupt = files.Write(L"corrupt.crt", Bytes{'b','a','d'});
    const auto empty = files.Write(L"empty.p7b", Pkcs7({}, {}));
    const auto valid = files.Write(L"valid.p7b", Chain());
    std::vector<std::wstring> log;
    ExpectSummary(ImportFiles({corrupt, empty, valid}, Settings(),
                              [&log](const std::wstring& line) { log.push_back(line); }, stores.Opener()), 4, 0, 2);
    Require(!log.empty(), "Import progress/errors must be logged");
    Require(stores.requests.size() == 4, "A malformed file stopped later valid objects");
    stores.CloseChecked();
}

void TestOneObjectOpenErrorContinues() {
    TempDirectory files;
    MemoryStores stores;
    size_t attempts = 0;
    StoreOpener opener = [&stores, &attempts](const std::wstring& name, Location location) -> HCERTSTORE {
        ++attempts;
        if (name == L"Root") {
            SetLastError(ERROR_ACCESS_DENIED);
            return nullptr;
        }
        return stores.Open(name, location);
    };
    const auto chain = files.Write(L"chain.p7b", Chain());
    ExpectSummary(ImportFiles({chain}, Settings(), QuietLog, opener), 3, 0, 1);
    Require(attempts == 4, "An object-level error stopped remaining PKCS7 objects");
    Require(Certificates(stores.At(L"My", Location::CurrentUser)).size() == 1, "Leaf was skipped after object error");
    Require(Crls(stores.At(L"CA", Location::CurrentUser)).size() == 1, "CRL was skipped after object error");
    stores.CloseChecked();
}

void TestDryRunNeverOpensDestinationStores() {
    TempDirectory files;
    const Bytes chain = Chain();
    const std::vector<std::wstring> paths{
        files.Write(L"der.p7b", chain), files.Write(L"pem.p7b", Base64(chain, "PKCS7")),
        files.Write(L"base64.p7b", Base64(chain)), files.Write(L"root.crt", Decode(testfixtures::ROOT))};
    size_t calls = 0;
    StoreOpener forbidden = [&calls](const std::wstring&, Location) -> HCERTSTORE {
        ++calls;
        throw std::runtime_error("Dry-run attempted to open a destination store");
    };
    ExpectSummary(ImportFiles(paths, Settings(Location::LocalMachine, StoreMode::Root, true), QuietLog, forbidden),
                  0, 0, 0, 13);
    Require(calls == 0, "Dry-run called the destination opener");
}

void TestRealContentControlsParsing() {
    TempDirectory files;
    MemoryStores stores;
    const auto cert = files.Write(L"certificate.crl", Decode(testfixtures::ROOT));
    const auto crl = files.Write(L"list.crt", Decode(testfixtures::CRL_OLD));
    const auto p7b = files.Write(L"container.crt", Chain());
    ExpectSummary(ImportFiles({cert, crl, p7b}, Settings(), QuietLog, stores.Opener()), 4, 2, 0);
    Require(stores.Size() == 3, "Content-based dispatch failed for renamed files");
    stores.CloseChecked();
}

void TestPemBundleReadsEverySupportedBlock() {
    TempDirectory files;
    MemoryStores stores;
    Bytes bundle{0xEF, 0xBB, 0xBF};
    const char preamble[] = "Bag Attributes\r\nsubject=public fixture\r\n";
    Append(bundle, Bytes(preamble, preamble + std::strlen(preamble)));
    for (const char* certificate : {testfixtures::ROOT, testfixtures::INTERMEDIATE, testfixtures::LEAF})
        Append(bundle, Base64(Decode(certificate), "CERTIFICATE"));
    Append(bundle, Base64(Decode(testfixtures::CRL_OLD), "X509 CRL"));
    Append(bundle, Base64(Chain(), "PKCS7"));
    const auto path = files.Write(L"full-chain.PeM", bundle);
    ExpectSummary(ImportFiles({path}, Settings(), QuietLog, stores.Opener()), 4, 4, 0);
    Require(Certificates(stores.At(L"Root", Location::CurrentUser)) ==
                std::vector<Bytes>{Decode(testfixtures::ROOT)}, "PEM bundle lost root bytes");
    Require(Certificates(stores.At(L"CA", Location::CurrentUser)) ==
                std::vector<Bytes>{Decode(testfixtures::INTERMEDIATE)}, "PEM bundle lost intermediate bytes");
    Require(Certificates(stores.At(L"My", Location::CurrentUser)) ==
                std::vector<Bytes>{Decode(testfixtures::LEAF)}, "PEM bundle lost leaf bytes");
    Require(Crls(stores.At(L"CA", Location::CurrentUser)) ==
                std::vector<Bytes>{Decode(testfixtures::CRL_OLD)}, "PEM bundle lost CRL bytes");
    stores.CloseChecked();
}

void TestMalformedPemBlockDoesNotHideLaterCertificates() {
    TempDirectory files;
    MemoryStores stores;
    Bytes bundle = Base64(Decode(testfixtures::ROOT), "CERTIFICATE");
    const char corrupt[] = "-----BEGIN CERTIFICATE-----\r\n%%invalid%%\r\n-----END CERTIFICATE-----\r\n";
    Append(bundle, Bytes(corrupt, corrupt + std::strlen(corrupt)));
    Append(bundle, Base64(Decode(testfixtures::LEAF), "CERTIFICATE"));
    std::vector<std::wstring> log;
    const auto path = files.Write(L"partly-broken.pem", bundle);
    ExpectSummary(ImportFiles({path}, Settings(), [&log](const std::wstring& line) { log.push_back(line); },
                               stores.Opener()), 2, 0, 1);
    Require(std::any_of(log.begin(), log.end(), [](const std::wstring& line) {
                return line.find(L"PEM-блок #2") != std::wstring::npos;
            }), "Malformed PEM block was not identified in log");
    Require(Certificates(stores.At(L"My", Location::CurrentUser)).size() == 1,
            "Malformed PEM block prevented the later leaf import");
    stores.CloseChecked();
}

void TestMalformedPemBoundariesAndUnsupportedKeysAreReported() {
    TempDirectory files;
    MemoryStores stores;
    const char beginning[] = "-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAAAA\n";
    Bytes bundle(beginning, beginning + std::strlen(beginning));
    Append(bundle, Base64(Decode(testfixtures::ROOT), "CERTIFICATE"));
    const char ending[] = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END X509 CRL-----\n"
                          "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"
                          "-----BEGIN CERTIFICATE-----\nAAAA\n";
    Append(bundle, Bytes(ending, ending + std::strlen(ending)));
    const auto broken = files.Write(L"broken-boundaries.pem", bundle);
    const auto later = files.Write(L"later.der", Decode(testfixtures::LEAF));
    ExpectSummary(ImportFiles({broken, later}, Settings(), QuietLog, stores.Opener()), 2, 0, 5);
    stores.CloseChecked();
}

void TestDerP7cSstAndSerializedPemLikeProperty() {
    TempDirectory files;
    MemoryStores stores;
    const auto der = files.Write(L"root.DER", Decode(testfixtures::ROOT));
    const auto p7c = files.Write(L"chain.P7c", Chain());
    const auto sst = files.Write(L"root-store.SST", SerializedStore(true));
    ExpectSummary(ImportFiles({der, p7c, sst}, Settings(), QuietLog, stores.Opener()), 4, 5, 0);
    Require(Certificates(stores.At(L"Root", Location::CurrentUser)).size() == 1, "SST lost root");
    Require(Certificates(stores.At(L"CA", Location::CurrentUser)).size() == 1, "SST lost intermediate");
    Require(Certificates(stores.At(L"My", Location::CurrentUser)).size() == 1, "SST lost leaf");
    Require(Crls(stores.At(L"CA", Location::CurrentUser)).size() == 1, "SST lost CRL");
    stores.CloseChecked();
}

void TestPfxEmptyAndNullPasswordAndCertificateOnly() {
    TempDirectory files;
    const Bytes encoded = Decode(extended_test_fixtures::PFX_EMPTY);
    CRYPT_DATA_BLOB blob = {static_cast<DWORD>(encoded.size()), const_cast<BYTE*>(encoded.data())};
    Require(PFXVerifyPassword(&blob, L"", 0) != FALSE && PFXVerifyPassword(&blob, nullptr, 0) != FALSE,
            "Unprotected PFX fixture must accept empty and NULL passwords without importing keys");
    const auto empty = files.Write(L"empty-password.P12", encoded);
    const auto certOnly = files.Write(L"certificates-only.pfx", Decode(extended_test_fixtures::PFX_CERT_ONLY));
    MemoryStores stores;
    EphemeralPfxProbe probe;
    Options options = Settings();
    size_t prompts = 0;
    options.passwordPrompt = [&prompts](const std::wstring&, bool, std::wstring&) {
        ++prompts;
        return false;
    };
    ExpectSummary(ImportFiles({empty, certOnly}, options, QuietLog, stores.Opener(), probe.Importer()), 2, 2, 0);
    Require(prompts == 0, "Empty/NULL PFX must not request a password");
    Require(probe.requestedFlags.size() == 2 && probe.privateKeys == 1,
            "PFX key or certificate-only container was not processed correctly");
    Require(!(probe.requestedFlags[0] & PKCS12_NO_PERSIST_KEY),
            "Production import flags unexpectedly disabled persistence");
    ExpectProviderAssociation(stores.At(L"My", Location::CurrentUser), Location::CurrentUser);
    stores.CloseChecked();
}

void TestPfxPasswordRetryAndSecretIsNotLogged() {
    TempDirectory files;
    MemoryStores stores;
    EphemeralPfxProbe probe;
    const auto path = files.Write(L"protected.pfx", Decode(extended_test_fixtures::PFX_PASSWORD));
    std::vector<bool> retries;
    std::vector<std::wstring> log;
    Options options = Settings();
    const std::wstring correct(extended_test_fixtures::TEST_PASSWORD,
                               extended_test_fixtures::TEST_PASSWORD + std::strlen(extended_test_fixtures::TEST_PASSWORD));
    options.passwordPrompt = [&](const std::wstring& requested, bool retry, std::wstring& password) {
        Require(requested == path, "Password prompt lost the file path");
        retries.push_back(retry);
        Require(retries.size() <= 2, "Password verification unexpectedly kept retrying");
        password = retry ? correct : L"wrong-secret-not-for-log";
        return true;
    };
    ExpectSummary(ImportFiles({path}, options, [&log](const std::wstring& line) { log.push_back(line); },
                               stores.Opener(), probe.Importer()), 2, 0, 0);
    Require(retries == std::vector<bool>({false, true}), "Password prompt retry sequence is incorrect");
    Require(probe.requestedFlags.size() == 1 && probe.privateKeys == 1,
            "Incorrect password attempt reached the key importer");
    for (const auto& line : log)
        Require(line.find(correct) == std::wstring::npos && line.find(L"wrong-secret-not-for-log") == std::wstring::npos,
                "PFX password was exposed in a log line");
    stores.CloseChecked();
}

void TestPfxCancelAndMissingPromptContinueBatch() {
    TempDirectory files;
    const auto protectedFile = files.Write(L"cancelled.p12", Decode(extended_test_fixtures::PFX_PASSWORD));
    const auto later = files.Write(L"later.cer", Decode(testfixtures::ROOT));
    MemoryStores stores;
    EphemeralPfxProbe probe;
    Options options = Settings();
    size_t prompts = 0;
    options.passwordPrompt = [&prompts](const std::wstring&, bool retry, std::wstring& password) {
        ++prompts;
        if (retry) return false;
        password = L"incorrect-then-cancel";
        return true;
    };
    ExpectSummary(ImportFiles({protectedFile, later}, options, QuietLog, stores.Opener(), probe.Importer()),
                  1, 0, 0, 0, 1);
    Require(prompts == 2 && probe.requestedFlags.empty(), "Cancelled PFX imported a key or skipped retry");
    stores.CloseChecked();
    MemoryStores second;
    ExpectSummary(ImportFiles({protectedFile, later}, Settings(), QuietLog, second.Opener(), probe.Importer()),
                  1, 0, 1);
    Require(probe.requestedFlags.empty(), "PFX without password callback reached key import");
    second.CloseChecked();
}

void TestPfxDuplicatePublicCertificateGainsProviderAssociation() {
    TempDirectory files;
    const auto plain = files.Write(L"public.cer", Decode(extended_test_fixtures::PFX_LEAF));
    const auto pfx = files.Write(L"identity.pfx", Decode(extended_test_fixtures::PFX_EMPTY));
    for (Location location : {Location::CurrentUser, Location::LocalMachine}) {
        for (StoreMode mode : {StoreMode::Automatic, StoreMode::Root}) {
            MemoryStores stores;
            EphemeralPfxProbe probe;
            const Options options = Settings(location, mode);
            ExpectSummary(ImportFiles({plain}, options, QuietLog, stores.Opener(), probe.Importer()), 1, 0, 0);
            ExpectSummary(ImportFiles({pfx}, options, QuietLog, stores.Opener(), probe.Importer()), 2, 0, 0);
            const std::wstring leafStore = mode == StoreMode::Root ? L"Root" : L"My";
            ExpectProviderAssociation(stores.At(leafStore, location), location);
            const auto before = Certificates(stores.At(leafStore, location));
            ExpectSummary(ImportFiles({pfx, plain}, options, QuietLog, stores.Opener(), probe.Importer()), 1, 2, 0);
            Require(Certificates(stores.At(leafStore, location)) == before,
                    "PFX merge duplicated or replaced the existing public certificate bytes");
            ExpectProviderAssociation(stores.At(leafStore, location), location);
            Require(probe.privateKeys == 2, "PFX source private key is unavailable");
            for (DWORD flags : probe.requestedFlags) {
                Require(!(flags & PKCS12_NO_PERSIST_KEY), "Production path should request persistent key import");
                Require(static_cast<bool>(flags & CRYPT_MACHINE_KEYSET) == (location == Location::LocalMachine),
                        "PFX private key scope differs from certificate store scope");
            }
            for (const auto& request : stores.requests) {
                Require(request.second == location, "PFX certificate store scope was lost");
                if (mode == StoreMode::Root) Require(request.first == L"Root", "PFX Root override was lost");
            }
            stores.CloseChecked();
        }
    }
}

void TestPfxDryRunDoesNotPersistKeysOrOpenDestinations() {
    TempDirectory files;
    const auto empty = files.Write(L"empty.pfx", Decode(extended_test_fixtures::PFX_EMPTY));
    const auto protectedFile = files.Write(L"protected.p12", Decode(extended_test_fixtures::PFX_PASSWORD));
    EphemeralPfxProbe probe;
    probe.addSyntheticProviderInfo = false;
    size_t destinationCalls = 0;
    const StoreOpener forbidden = [&destinationCalls](const std::wstring&, Location) -> HCERTSTORE {
        ++destinationCalls;
        throw std::runtime_error("PFX dry-run attempted destination write");
    };
    Options options = Settings(Location::LocalMachine, StoreMode::Root, true);
    options.passwordPrompt = [](const std::wstring&, bool, std::wstring& password) {
        password.assign(extended_test_fixtures::TEST_PASSWORD,
                         extended_test_fixtures::TEST_PASSWORD + std::strlen(extended_test_fixtures::TEST_PASSWORD));
        return true;
    };
    ExpectSummary(ImportFiles({empty, protectedFile}, options, QuietLog, forbidden, probe.Importer()), 0, 0, 0, 4);
    Require(destinationCalls == 0 && probe.privateKeys == 2, "PFX dry-run opened store or failed to read keys");
    for (DWORD flags : probe.requestedFlags)
        Require((flags & PKCS12_NO_PERSIST_KEY) && (flags & CRYPT_MACHINE_KEYSET),
                "PFX dry-run did not request ephemeral keys in the selected scope");
}

void TestPfxImporterErrorContinuesBatch() {
    TempDirectory files;
    MemoryStores stores;
    const auto pfx = files.Write(L"failed-import.pfx", Decode(extended_test_fixtures::PFX_EMPTY));
    const auto later = files.Write(L"later.cer", Decode(testfixtures::ROOT));
    size_t calls = 0;
    const PfxImporter denied = [&calls](CRYPT_DATA_BLOB*, LPCWSTR, DWORD) -> HCERTSTORE {
        ++calls;
        SetLastError(ERROR_ACCESS_DENIED);
        return nullptr;  // No real key importer is ever called in this test.
    };
    ExpectSummary(ImportFiles({pfx, later}, Settings(), QuietLog, stores.Opener(), denied), 1, 0, 1);
    Require(calls == 1, "A verified-password provider failure should not prompt/import repeatedly");
    stores.CloseChecked();
}

void TestPfxPromptExceptionDoesNotExposeSecret() {
    TempDirectory files;
    MemoryStores stores;
    EphemeralPfxProbe probe;
    const auto pfx = files.Write(L"prompt-error.pfx", Decode(extended_test_fixtures::PFX_PASSWORD));
    const auto later = files.Write(L"later.cer", Decode(testfixtures::ROOT));
    Options options = Settings();
    options.passwordPrompt = [](const std::wstring&, bool, std::wstring&) -> bool {
        throw std::runtime_error(extended_test_fixtures::TEST_PASSWORD);
    };
    std::vector<std::wstring> log;
    ExpectSummary(ImportFiles({pfx, later}, options, [&log](const std::wstring& line) { log.push_back(line); },
                               stores.Opener(), probe.Importer()), 1, 0, 1);
    const std::wstring secret(extended_test_fixtures::TEST_PASSWORD,
                              extended_test_fixtures::TEST_PASSWORD + std::strlen(extended_test_fixtures::TEST_PASSWORD));
    for (const auto& line : log)
        Require(line.find(secret) == std::wstring::npos, "Password prompt exception exposed secret in log");
    Require(probe.requestedFlags.empty(), "Failed password prompt reached key import");
    stores.CloseChecked();
}
}  // namespace

int main() {
    struct Test { const char* name; void (*run)(); };
    const Test tests[] = {
        {"classification_root_intermediate_leaf_and_self_issued", TestClassification},
        {"legacy_modern_and_missing_basic_constraints", TestBasicConstraintsPolicies},
        {"single_der_pem_duplicates", TestSingleCertificateDerPemDuplicates},
        {"cer_der_pem_mixed_case_extensions_and_scopes", TestCerDerPemAndMixedCaseExtensions},
        {"pkcs7_der_pem_base64_all_objects_and_duplicates", TestPkcs7DerPemBase64AndDuplicates},
        {"scope_and_mode_apply_to_every_object", TestAllScopesAndStoreModes},
        {"newer_crl_replaces_old_without_downgrade", TestCrlNewerReplacesAndOlderDoesNotOverwrite},
        {"cert_only_and_crl_only_pkcs7", TestCertOnlyAndCrlOnlyPkcs7},
        {"corrupt_and_empty_files_continue", TestCorruptAndEmptyFilesContinue},
        {"one_object_error_continues", TestOneObjectOpenErrorContinues},
        {"dry_run_never_opens_destination", TestDryRunNeverOpensDestinationStores},
        {"actual_content_controls_parsing", TestRealContentControlsParsing},
        {"pem_bundle_reads_all_certificate_crl_pkcs7_blocks", TestPemBundleReadsEverySupportedBlock},
        {"malformed_pem_block_does_not_hide_later_certificates", TestMalformedPemBlockDoesNotHideLaterCertificates},
        {"malformed_pem_boundaries_and_private_key_are_reported", TestMalformedPemBoundariesAndUnsupportedKeysAreReported},
        {"der_p7c_sst_and_serialized_pem_like_property", TestDerP7cSstAndSerializedPemLikeProperty},
        {"pfx_empty_null_password_and_certificate_only", TestPfxEmptyAndNullPasswordAndCertificateOnly},
        {"pfx_password_retry_without_secret_in_logs", TestPfxPasswordRetryAndSecretIsNotLogged},
        {"pfx_cancel_and_missing_prompt_continue_batch", TestPfxCancelAndMissingPromptContinueBatch},
        {"pfx_public_duplicate_merges_key_provider_association", TestPfxDuplicatePublicCertificateGainsProviderAssociation},
        {"pfx_dry_run_never_persists_keys_or_opens_destinations", TestPfxDryRunDoesNotPersistKeysOrOpenDestinations},
        {"pfx_importer_failure_continues_batch", TestPfxImporterErrorContinuesBatch},
        {"pfx_prompt_exception_does_not_expose_secret", TestPfxPromptExceptionDoesNotExposeSecret},
    };
    size_t failures = 0;
    for (const auto& test : tests) {
        try {
            test.run();
            std::cout << "[PASS] " << test.name << '\n';
        } catch (const std::exception& error) {
            ++failures;
            std::cerr << "[FAIL] " << test.name << ": " << error.what() << '\n';
        } catch (...) {
            ++failures;
            std::cerr << "[FAIL] " << test.name << ": unknown exception\n";
        }
    }
    const size_t total = sizeof(tests) / sizeof(tests[0]);
    std::cout << (total - failures) << "/" << total << " tests passed; all writes used MEMORY stores.\n";
    return failures ? 1 : 0;
}
