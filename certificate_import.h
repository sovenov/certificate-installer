#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

namespace certinstaller {

enum class Location { CurrentUser, LocalMachine };
enum class StoreMode { Automatic, Root };

// Called on the importing thread. Return false to cancel this file only.
// retry is false on the first prompt and true after an incorrect password.
// The backend securely clears the returned password after each attempt.
using PasswordPrompt = std::function<bool(const std::wstring& path, bool retry,
                                         std::wstring& password)>;

struct Options {
    Location location = Location::CurrentUser;
    StoreMode mode = StoreMode::Automatic;
    bool dryRun = false;
    PasswordPrompt passwordPrompt;
};

struct Summary {
    std::size_t installed = 0;
    std::size_t skipped = 0;
    std::size_t errors = 0;
    std::size_t planned = 0;
    std::size_t cancelled = 0;
};

// Called synchronously on the thread running ImportFiles. The sink must not throw.
using LogSink = std::function<void(const std::wstring&)>;

// A successful opener transfers one store-handle reference to the backend.
// The backend always closes it. Tests can return CertDuplicateStore(memoryStore).
// On failure return nullptr and set GetLastError, or throw std::exception.
using StoreOpener = std::function<HCERTSTORE(const std::wstring&, Location)>;

// Test seam: owns the returned store reference. A test importer must add
// PKCS12_NO_PERSIST_KEY and use only memory destination stores. The production
// default persists keys for the chosen user/machine scope; dryRun never does.
using PfxImporter = std::function<HCERTSTORE(CRYPT_DATA_BLOB*, LPCWSTR, DWORD)>;

// Imports all certificates/CRLs from DER, multi-block PEM, PKCS#7, SST, or PFX.
// Counters describe objects; a file read/enumeration/empty-file
// failure contributes one error. Object errors do not stop the remaining batch.
// dryRun never calls the opener and never opens or changes destination stores.
Summary ImportFiles(const std::vector<std::wstring>& paths,
                    const Options& options,
                    const LogSink& log,
                    const StoreOpener& opener = StoreOpener(),
                    const PfxImporter& pfxImporter = PfxImporter());

bool IsAdministrator();

// Includes a readable system message when available and the 32-bit hex code.
std::wstring FormatWindowsError(DWORD error);

// Explicit policy matching install_certificates.py, rather than the Windows
// import wizard: self-signed CA -> Root; other CA/CRL -> CA; end entity -> My.
// CA is detected using Basic Constraints v2, then the legacy v1 extension.
// Certificates without Basic Constraints are end entities under this policy.
// Throws std::exception on malformed constraints or unavailable signature APIs.
std::wstring SelectStore(DWORD kind, const void* context, StoreMode mode);

}  // namespace certinstaller
