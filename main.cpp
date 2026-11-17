#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <process.h>
#include <algorithm>
#include <memory>
#include <string>
#include <vector>
#include "resource.h"
#include "certificate_import.h"

namespace {
constexpr UINT WM_LOG_LINE = WM_APP + 1;
constexpr UINT WM_IMPORT_DONE = WM_APP + 2;
constexpr UINT WM_START_IMPORT = WM_APP + 3;
constexpr UINT WM_UI_SMOKE = WM_APP + 4;
constexpr UINT WM_PASSWORD_REQUEST = WM_APP + 5;
constexpr UINT_PTR FILE_PICKER_TIMER = 2;
constexpr UINT WM_COPYGLOBALDATA_COMPAT = 0x0049;
constexpr wchar_t FILE_PICKER_TITLE[] = L"Выберите один или несколько файлов";

struct App {
    HWND window = nullptr;
    HFONT logFont = nullptr;
    HICON largeIcon = nullptr;
    HICON smallIcon = nullptr;
    std::vector<std::wstring> files;
    std::wstring log;
    bool busy = false;
    bool machine = false;
    bool root = false;
    bool startImport = false;
    bool smoke = false;
    std::wstring smokeDirectory;
    int dpi = 96;
    int exitCode = 0;

    ~App() {
        if (largeIcon) DestroyIcon(largeIcon);
        if (smallIcon) DestroyIcon(smallIcon);
    }
};

struct Job {
    HWND window;
    std::vector<std::wstring> files;
    certinstaller::Options options;
};

struct PasswordRequest {
    const std::wstring* path;
    bool retry;
    std::wstring* password;
    bool accepted = false;
};

std::wstring Number(size_t value) { return std::to_wstring(value); }

std::wstring WindowText(HWND control) {
    const int count = GetWindowTextLengthW(control);
    std::vector<wchar_t> buffer(static_cast<size_t>(count) + 1);
    GetWindowTextW(control, buffer.data(), count + 1);
    return buffer.data();
}

void AppendLog(App& app, const std::wstring& line) {
    const std::wstring text = line + L"\r\n";
    // Ограничение относится только к видимому полю: полный журнал сохраняется отдельно.
    app.log += text;
    HWND edit = GetDlgItem(app.window, IDC_LOG);
    if (GetWindowTextLengthW(edit) > 2000000) SetWindowTextW(edit, L"[Ранние строки доступны в сохранённом журнале.]\r\n");
    SendMessageW(edit, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
    SendMessageW(edit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
    SendMessageW(edit, EM_SCROLLCARET, 0, 0);
}

void Status(App& app, const std::wstring& text) {
    SetDlgItemTextW(app.window, IDC_STATUS, text.c_str());
}

void UpdateStoreHint(App& app) {
    const bool root = SendDlgItemMessageW(app.window, IDC_STORE, CB_GETCURSEL, 0, 0) == 1;
    SetDlgItemTextW(app.window, IDC_HINT, root ? L"Все выбранные сертификаты и CRL будут помещены в Root. Выбирайте этот режим только для доверенных файлов."
                      : L"Авто: корневые CA → Root; остальные CA и CRL → CA; конечные → My.");
}

void RefreshButtons(App& app) {
    const bool hasFiles = !app.files.empty();
    for (int id : {IDC_ADD, IDC_FILES, IDC_LOCATION, IDC_STORE})
        EnableWindow(GetDlgItem(app.window, id), !app.busy);
    EnableWindow(GetDlgItem(app.window, IDC_REMOVE), !app.busy && hasFiles);
    EnableWindow(GetDlgItem(app.window, IDC_CLEAR), !app.busy && hasFiles);
    EnableWindow(GetDlgItem(app.window, IDC_INSTALL), !app.busy && hasFiles);
    EnableWindow(GetDlgItem(app.window, IDC_CHECK), !app.busy && hasFiles);
    EnableWindow(GetDlgItem(app.window, IDC_SAVELOG), !app.log.empty());
    const bool machine = SendDlgItemMessageW(app.window, IDC_LOCATION, CB_GETCURSEL, 0, 0) == 1;
    SendDlgItemMessageW(app.window, IDC_INSTALL, BCM_SETSHIELD, 0,
                       machine && !certinstaller::IsAdministrator());
}

std::wstring FullPath(const std::wstring& path) {
    const DWORD size = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (!size) return path;
    std::vector<wchar_t> buffer(static_cast<size_t>(size) + 1);
    if (!GetFullPathNameW(path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr)) return path;
    return buffer.data();
}

std::wstring FileName(const std::wstring& path) {
    const auto separator = path.find_last_of(L"\\/");
    return separator == std::wstring::npos ? path : path.substr(separator + 1);
}

bool SupportedExtension(const std::wstring& extension) {
    const wchar_t* values[] = {L".crt", L".cer", L".crl", L".p7b", L".pem", L".der",
                              L".p7c", L".sst", L".pfx", L".p12"};
    for (const wchar_t* value : values)
        if (!_wcsicmp(extension.c_str(), value)) return true;
    return false;
}

bool AddPath(App& app, const std::wstring& candidate) {
    const std::wstring path = FullPath(candidate);
    const auto dot = path.find_last_of(L'.');
    const std::wstring extension = dot == std::wstring::npos ? L"" : path.substr(dot);
    if (!SupportedExtension(extension)) {
        AppendLog(app, L"[НЕ ДОБАВЛЕН] " + path + L": поддерживаются .crt, .cer, .crl, .pem, .der, .p7b, .p7c, .sst, .pfx и .p12.");
        return false;
    }
    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        AppendLog(app, L"[НЕ ДОБАВЛЕН] " + path + L": файл не найден или это папка.");
        return false;
    }
    for (const auto& existing : app.files)
        if (!_wcsicmp(existing.c_str(), path.c_str())) return false;
    app.files.push_back(path);
    return true;
}

void RefreshFiles(App& app) {
    HWND list = GetDlgItem(app.window, IDC_FILES);
    ListView_DeleteAllItems(list);
    for (size_t index = 0; index < app.files.size(); ++index) {
        const std::wstring name = FileName(app.files[index]);
        const auto separator = app.files[index].find_last_of(L"\\/");
        const std::wstring folder = separator == std::wstring::npos ? L"" : app.files[index].substr(0, separator);
        LVITEMW item = {};
        item.mask = LVIF_TEXT;
        item.iItem = static_cast<int>(index);
        item.pszText = const_cast<wchar_t*>(name.c_str());
        const int row = ListView_InsertItem(list, &item);
        ListView_SetItemText(list, row, 1, const_cast<wchar_t*>(folder.c_str()));
    }
    Status(app, L"Выбрано файлов: " + Number(app.files.size()));
    RefreshButtons(app);
}

void SizeFilePicker(HWND window, HWND owner, int dpi) {
    MONITORINFO information = {};
    information.cbSize = sizeof(information);
    RECT work = {};
    if (GetMonitorInfoW(MonitorFromWindow(owner, MONITOR_DEFAULTTONEAREST), &information))
        work = information.rcWork;
    else if (!SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0)) {
        work.right = GetSystemMetrics(SM_CXSCREEN);
        work.bottom = GetSystemMetrics(SM_CYSCREEN);
    }
    RECT anchor = {};
    if (!GetWindowRect(owner, &anchor)) anchor = work;
    RECT bounds = {};
    if (!IntersectRect(&bounds, &anchor, &work)) bounds = work;
    const int availableWidth = static_cast<int>(bounds.right - bounds.left);
    const int availableHeight = static_cast<int>(bounds.bottom - bounds.top);
    const int margin = MulDiv(12, dpi, 96);
    const int insetX = (std::min)(margin, (std::max)(0, (availableWidth - 1) / 2));
    const int insetY = (std::min)(margin, (std::max)(0, (availableHeight - 1) / 2));
    // Keep a small, equal border of the main window visible around the picker.
    SetWindowPos(window, nullptr, bounds.left + insetX, bounds.top + insetY,
        (std::max)(1, availableWidth - 2 * insetX), (std::max)(1, availableHeight - 2 * insetY),
        SWP_NOZORDER | SWP_NOACTIVATE);
}

BOOL CALLBACK ResizeReadyFilePicker(HWND window, LPARAM parameter) {
    App* app = reinterpret_cast<App*>(parameter);
    if (!IsWindowVisible(window) || GetWindow(window, GW_OWNER) != app->window) return TRUE;
    wchar_t className[32] = {}, title[128] = {};
    GetClassNameW(window, className, ARRAYSIZE(className));
    GetWindowTextW(window, title, ARRAYSIZE(title));
    if (wcscmp(className, L"#32770") || wcscmp(title, FILE_PICKER_TITLE)) return TRUE;
    KillTimer(app->window, FILE_PICKER_TIMER);
    SizeFilePicker(window, app->window, app->dpi);
    return FALSE;
}

void CALLBACK FilePickerSizeTimer(HWND owner, UINT, UINT_PTR, DWORD) {
    App* app = reinterpret_cast<App*>(GetWindowLongPtrW(owner, DWLP_USER));
    if (app) EnumThreadWindows(GetCurrentThreadId(), ResizeReadyFilePicker, reinterpret_cast<LPARAM>(app));
}

void ChooseFiles(App& app) {
    std::vector<wchar_t> names(262144, L'\0');
    OPENFILENAMEW dialog = {};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = app.window;
    dialog.lpstrFilter = L"Сертификаты, CRL и контейнеры\0*.crt;*.cer;*.crl;*.pem;*.der;*.p7b;*.p7c;*.sst;*.pfx;*.p12\0Все файлы\0*.*\0\0";
    dialog.lpstrFile = names.data();
    dialog.nMaxFile = static_cast<DWORD>(names.size());
    dialog.lpstrTitle = FILE_PICKER_TITLE;
    dialog.Flags = OFN_EXPLORER | OFN_ALLOWMULTISELECT | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_ENABLESIZING;
    // Let the native dialog finish restoring its layout before setting its size.
    // A timer runs inside the modal loop, without enabling the older OFN hook UI.
    SetTimer(app.window, FILE_PICKER_TIMER, 100, FilePickerSizeTimer);
    const BOOL selected = GetOpenFileNameW(&dialog);
    KillTimer(app.window, FILE_PICKER_TIMER);
    if (!selected) {
        const DWORD error = CommDlgExtendedError();
        if (error) AppendLog(app, L"[ОШИБКА] Выбор файлов: " + certinstaller::FormatWindowsError(error));
        RefreshButtons(app);
        return;
    }
    const std::wstring first = names.data();
    const wchar_t* next = names.data() + first.size() + 1;
    if (!*next) AddPath(app, first);
    else for (; *next; next += wcslen(next) + 1) AddPath(app, first + L"\\" + next);
    RefreshFiles(app);
}

void DropFiles(App& app, HDROP drop) {
    if (!app.busy) {
        const UINT count = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
        for (UINT index = 0; index < count; ++index) {
            const UINT size = DragQueryFileW(drop, index, nullptr, 0);
            std::vector<wchar_t> path(static_cast<size_t>(size) + 1);
            if (DragQueryFileW(drop, index, path.data(), size + 1)) AddPath(app, path.data());
        }
        RefreshFiles(app);
    }
    DragFinish(drop);
}

bool WriteUtf8(const std::wstring& filename, const std::wstring& text, DWORD& error) {
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (size == 0 && !text.empty()) { error = GetLastError(); return false; }
    std::vector<char> bytes(static_cast<size_t>(size));
    if (size) WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), bytes.data(), size, nullptr, nullptr);
    HANDLE file = CreateFileW(filename.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) { error = GetLastError(); return false; }
    DWORD written = 0;
    const char bom[] = {static_cast<char>(0xEF), static_cast<char>(0xBB), static_cast<char>(0xBF)};
    bool ok = WriteFile(file, bom, sizeof(bom), &written, nullptr) && written == sizeof(bom);
    if (ok && size) ok = WriteFile(file, bytes.data(), static_cast<DWORD>(size), &written, nullptr) && written == static_cast<DWORD>(size);
    error = ok ? ERROR_SUCCESS : GetLastError();
    if (!CloseHandle(file) && ok) { ok = false; error = GetLastError(); }
    return ok;
}

void SaveLog(App& app) {
    std::vector<wchar_t> name(32768, 0);
    wcscpy_s(name.data(), name.size(), L"certificate-install.log");
    OPENFILENAMEW dialog = {};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = app.window;
    dialog.lpstrFilter = L"Журнал (*.log)\0*.log\0Текст (*.txt)\0*.txt\0\0";
    dialog.lpstrFile = name.data();
    dialog.nMaxFile = static_cast<DWORD>(name.size());
    dialog.lpstrDefExt = L"log";
    dialog.Flags = OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&dialog)) {
        const DWORD error = CommDlgExtendedError();
        if (error) AppendLog(app, L"[ОШИБКА] Сохранение журнала: " + certinstaller::FormatWindowsError(error));
        return;
    }
    DWORD error = 0;
    if (!WriteUtf8(name.data(), app.log, error))
        AppendLog(app, L"[ОШИБКА] Не удалось сохранить журнал: " + certinstaller::FormatWindowsError(error));
    else Status(app, L"Журнал сохранён: " + std::wstring(name.data()));
}

// Правила Windows CommandLineToArgvW: экранируются кавычки и обратные слеши перед ними.
std::wstring QuoteArgument(const std::wstring& argument) {
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (wchar_t character : argument) {
        if (character == L'\\') { ++slashes; continue; }
        if (character == L'\"') result.append(slashes * 2 + 1, L'\\');
        else result.append(slashes, L'\\');
        result += character;
        slashes = 0;
    }
    result.append(slashes * 2, L'\\');
    return result + L"\"";
}

bool RestartElevated(App& app, bool root) {
    std::vector<wchar_t> executable(32768, 0);
    const DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (!length || length >= executable.size()) {
        AppendLog(app, L"[ОШИБКА] Не удалось определить путь программы.");
        return false;
    }
    std::wstring parameters = root ? L"--machine --root --install --" : L"--machine --install --";
    for (const auto& file : app.files) parameters += L" " + QuoteArgument(file);
    if (parameters.size() + length + 4 > 30000) {
        AppendLog(app, L"[ОШИБКА] Для передачи такого количества путей запустите программу от имени администратора и выберите файлы заново.");
        return false;
    }
    SHELLEXECUTEINFOW request = {};
    request.cbSize = sizeof(request);
    request.fMask = SEE_MASK_NOCLOSEPROCESS;
    request.hwnd = app.window;
    request.lpVerb = L"runas";
    request.lpFile = executable.data();
    request.lpParameters = parameters.c_str();
    request.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&request)) {
        const DWORD error = GetLastError();
        AppendLog(app, error == ERROR_CANCELLED ? L"[ОТМЕНА] Запрос прав администратора отменён. Файлы остались в списке."
                  : L"[ОШИБКА] Запрос прав администратора: " + certinstaller::FormatWindowsError(error));
        RefreshButtons(app);
        return false;
    }
    if (request.hProcess) CloseHandle(request.hProcess);
    DestroyWindow(app.window);
    return true;
}

unsigned __stdcall Worker(void* parameter) {
    std::unique_ptr<Job> job(static_cast<Job*>(parameter));
    std::unique_ptr<certinstaller::Summary> summary(new certinstaller::Summary());
    try {
        *summary = certinstaller::ImportFiles(job->files, job->options, [jobWindow = job->window](const std::wstring& line) {
            std::unique_ptr<std::wstring> text(new std::wstring(line));
            // GUI never waits for this worker. Synchronous delivery bounds the queue
            // and avoids losing logs/completion when PostMessage reaches its quota.
            if (IsWindow(jobWindow)) SendMessageW(jobWindow, WM_LOG_LINE, 0, reinterpret_cast<LPARAM>(text.release()));
        });
    } catch (...) {
        ++summary->errors;
        std::unique_ptr<std::wstring> text(new std::wstring(L"[ОШИБКА] Внутренняя ошибка обработки. Остальные операции остановлены."));
        if (IsWindow(job->window)) SendMessageW(job->window, WM_LOG_LINE, 0, reinterpret_cast<LPARAM>(text.release()));
    }
    if (IsWindow(job->window)) SendMessageW(job->window, WM_IMPORT_DONE, 0, reinterpret_cast<LPARAM>(summary.release()));
    return 0;
}

void StartImport(App& app, bool dryRun) {
    if (app.busy || app.files.empty()) return;
    const bool machine = SendDlgItemMessageW(app.window, IDC_LOCATION, CB_GETCURSEL, 0, 0) == 1;
    const bool root = SendDlgItemMessageW(app.window, IDC_STORE, CB_GETCURSEL, 0, 0) == 1;
    if (app.smoke) dryRun = true; // Автоматизированная проверка GUI никогда не устанавливает сертификаты.
    if (machine && !dryRun && !certinstaller::IsAdministrator()) { RestartElevated(app, root); return; }
    std::unique_ptr<Job> job(new Job());
    job->window = app.window;
    job->files = app.files;
    job->options.location = machine ? certinstaller::Location::LocalMachine : certinstaller::Location::CurrentUser;
    job->options.mode = root ? certinstaller::StoreMode::Root : certinstaller::StoreMode::Automatic;
    job->options.dryRun = dryRun;
    job->options.passwordPrompt = [window = app.window](const std::wstring& path, bool retry, std::wstring& password) {
        PasswordRequest request = {&path, retry, &password};
        if (IsWindow(window))
            SendMessageW(window, WM_PASSWORD_REQUEST, 0, reinterpret_cast<LPARAM>(&request));
        return request.accepted;
    };
    SYSTEMTIME now = {};
    GetLocalTime(&now);
    wchar_t stamp[64];
    swprintf_s(stamp, L"\r\n[%02u:%02u:%02u] %s. Файлов: %u.", now.wHour, now.wMinute, now.wSecond,
               dryRun ? L"Проверка без установки" : L"Установка", static_cast<unsigned>(app.files.size()));
    AppendLog(app, stamp);
    AppendLog(app, machine ? L"Расположение: локальный компьютер." : L"Расположение: текущий пользователь.");
    AppendLog(app, root ? L"Хранилище: все объекты в Root." : L"Хранилище: автоматически по типу.");
    app.busy = true;
    RefreshButtons(app);
    Status(app, L"Обработка…");
    uintptr_t thread = _beginthreadex(nullptr, 0, Worker, job.get(), 0, nullptr);
    if (!thread) {
        app.busy = false;
        AppendLog(app, L"[ОШИБКА] Не удалось запустить обработку.");
        Status(app, L"Обработка не запущена.");
        RefreshButtons(app);
        return;
    }
    job.release();
    CloseHandle(reinterpret_cast<HANDLE>(thread));
}

void Layout(App& app) {
    RECT client = {};
    GetClientRect(app.window, &client);
    const auto scale = [&app](int value) { return MulDiv(value, app.dpi, 96); };
    const int margin = scale(14), width = client.right - 2 * margin;
    const int extra = (std::max)(0, static_cast<int>(client.bottom) - scale(580));
    const int listHeight = scale(128) + extra / 3;
    auto move = [&app, &scale](int id, int x, int y, int w, int h) {
        MoveWindow(GetDlgItem(app.window, id), x, y, w, h, TRUE);
    };
    move(IDC_INTRO, margin, scale(11), width, scale(20));
    move(IDC_ADD, margin, scale(37), scale(138), scale(27));
    move(IDC_REMOVE, margin + scale(146), scale(37), scale(144), scale(27));
    move(IDC_CLEAR, margin + scale(298), scale(37), scale(138), scale(27));
    int y = scale(72);
    move(IDC_FILES, margin, y, width, listHeight);
    ListView_SetColumnWidth(GetDlgItem(app.window, IDC_FILES), 0, scale(210));
    ListView_SetColumnWidth(GetDlgItem(app.window, IDC_FILES), 1, (std::max)(scale(140), width - scale(230)));
    y += listHeight + scale(10);
    move(IDC_LOCATION_LABEL, margin, y, width, scale(18)); y += scale(20);
    move(IDC_LOCATION, margin, y, width, scale(150)); y += scale(35);
    move(IDC_STORE_LABEL, margin, y, width, scale(18)); y += scale(20);
    move(IDC_STORE, margin, y, width, scale(150)); y += scale(35);
    move(IDC_HINT, margin, y, width, scale(34)); y += scale(39);
    move(IDC_INSTALL, margin, y, scale(130), scale(33));
    move(IDC_CHECK, margin + scale(138), y, scale(122), scale(33));
    move(IDC_SAVELOG, client.right - margin - scale(170), y, scale(170), scale(33)); y += scale(43);
    move(IDC_STATUS, margin, y, width, scale(20)); y += scale(24);
    move(IDC_LOG, margin, y, width, (std::max)(scale(65), static_cast<int>(client.bottom) - margin - y));
}

void PositionInitialWindow(HWND window, int width, int height) {
    POINT pointer = {};
    const HMONITOR monitor = GetCursorPos(&pointer)
        ? MonitorFromPoint(pointer, MONITOR_DEFAULTTONEAREST)
        : MonitorFromWindow(GetForegroundWindow(), MONITOR_DEFAULTTOPRIMARY);
    MONITORINFO information = {};
    information.cbSize = sizeof(information);
    RECT work = {};
    if (GetMonitorInfoW(monitor, &information)) work = information.rcWork;
    else if (!SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0)) {
        work.right = GetSystemMetrics(SM_CXSCREEN);
        work.bottom = GetSystemMetrics(SM_CYSCREEN);
    }
    // Centre within the monitor's usable area, keeping the caption visible even
    // when the window is larger than a small screen. Monitor origins may be negative.
    const int x = work.left + (std::max)(0, (static_cast<int>(work.right - work.left) - width) / 2);
    const int y = work.top + (std::max)(0, (static_cast<int>(work.bottom - work.top) - height) / 2);
    SetWindowPos(window, nullptr, x, y, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
}

// Встроенная проверка интерфейса: принимает каталог с тестовыми файлами, выполняет только dry-run.
// Отчёт записывается UTF-8. Системные хранилища в этом режиме не открываются для записи.
void SmokeStart(App& app) {
    WIN32_FIND_DATAW data = {};
    const std::wstring mask = app.smokeDirectory + L"\\*";
    HANDLE search = FindFirstFileW(mask.c_str(), &data);
    std::vector<std::wstring> paths;
    if (search != INVALID_HANDLE_VALUE) {
        do { if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            const std::wstring name = data.cFileName;
            const auto dot = name.find_last_of(L'.');
            const std::wstring extension = dot == std::wstring::npos ? L"" : name.substr(dot);
            if (SupportedExtension(extension))
                paths.push_back(app.smokeDirectory + L"\\" + name);
        }} while (FindNextFileW(search, &data));
        FindClose(search);
    }
    // Проверяем тот же обработчик WM_DROPFILES, который используется при drag-and-drop.
    size_t characters = 1;
    for (const auto& path : paths) characters += path.size() + 1;
    HGLOBAL memory = GlobalAlloc(GHND, sizeof(DROPFILES) + characters * sizeof(wchar_t));
    if (memory) {
        auto drop = static_cast<DROPFILES*>(GlobalLock(memory));
        drop->pFiles = sizeof(DROPFILES);
        drop->fWide = TRUE;
        wchar_t* destination = reinterpret_cast<wchar_t*>(reinterpret_cast<BYTE*>(drop) + sizeof(DROPFILES));
        for (const auto& path : paths) {
            memcpy(destination, path.c_str(), (path.size() + 1) * sizeof(wchar_t));
            destination += path.size() + 1;
        }
        GlobalUnlock(memory);
        SendMessageW(app.window, WM_DROPFILES, reinterpret_cast<WPARAM>(memory), 0);
    }
    const auto original = app.files.size();
    for (const auto& path : paths) AddPath(app, path);
    if (original != app.files.size() || original == 0) app.exitCode = 2;
    SendDlgItemMessageW(app.window, IDC_LOCATION, CB_SETCURSEL, 1, 0);
    SendDlgItemMessageW(app.window, IDC_STORE, CB_SETCURSEL, 1, 0);
    UpdateStoreHint(app);
    RefreshButtons(app);
    StartImport(app, true);
    if (!app.busy) { app.exitCode = 2; DestroyWindow(app.window); }
}

INT_PTR CALLBACK PasswordDialogProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    auto request = reinterpret_cast<PasswordRequest*>(GetWindowLongPtrW(window, DWLP_USER));
    if (message == WM_INITDIALOG) {
        request = reinterpret_cast<PasswordRequest*>(lParam);
        SetWindowLongPtrW(window, DWLP_USER, lParam);
        SetDlgItemTextW(window, IDC_PASSWORD_FILE, request->path->c_str());
        if (request->retry) SetDlgItemTextW(window, IDC_PASSWORD_HINT,
            L"Не удалось открыть контейнер с этим паролем. Повторите ввод или пропустите файл.");
        RECT owner = {}, rectangle = {};
        GetWindowRect(GetParent(window), &owner);
        GetWindowRect(window, &rectangle);
        const int width = rectangle.right - rectangle.left, height = rectangle.bottom - rectangle.top;
        SetWindowPos(window, nullptr, owner.left + (owner.right - owner.left - width) / 2,
            owner.top + (owner.bottom - owner.top - height) / 2, 0, 0,
            SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        SetFocus(GetDlgItem(window, IDC_PASSWORD_VALUE));
        return FALSE;
    }
    if (!request) return FALSE;
    if (message == WM_COMMAND && LOWORD(wParam) == IDOK) {
        try {
            std::wstring& password = *request->password;
            if (!password.empty()) SecureZeroMemory(&password[0], password.size() * sizeof(wchar_t));
            password.clear();
            HWND edit = GetDlgItem(window, IDC_PASSWORD_VALUE);
            const int length = GetWindowTextLengthW(edit);
            password.resize(static_cast<size_t>(length) + 1);
            const int copied = GetWindowTextW(edit, &password[0], length + 1);
            password.resize(static_cast<size_t>(copied));
            request->accepted = true;
        } catch (...) {
            request->accepted = false;
        }
        SetDlgItemTextW(window, IDC_PASSWORD_VALUE, L"");
        EndDialog(window, request->accepted ? IDOK : IDCANCEL);
        return TRUE;
    }
    if ((message == WM_COMMAND && LOWORD(wParam) == IDCANCEL) || message == WM_CLOSE) {
        SetDlgItemTextW(window, IDC_PASSWORD_VALUE, L"");
        request->accepted = false;
        EndDialog(window, IDCANCEL);
        return TRUE;
    }
    return FALSE;
}

INT_PTR CALLBACK DialogProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    App* app = reinterpret_cast<App*>(GetWindowLongPtrW(window, DWLP_USER));
    if (message == WM_INITDIALOG) {
        app = reinterpret_cast<App*>(lParam);
        app->window = window;
        SetWindowLongPtrW(window, DWLP_USER, lParam);
        HDC screen = GetDC(window);
        app->dpi = GetDeviceCaps(screen, LOGPIXELSX);
        ReleaseDC(window, screen);
        HINSTANCE instance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(window, GWLP_HINSTANCE));
        // Own separate handles: LR_SHARED caches by resource name rather than size.
        app->largeIcon = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON,
            GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), 0));
        app->smallIcon = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON,
            GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0));
        if (app->largeIcon) SendMessageW(window, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(app->largeIcon));
        if (app->smallIcon) SendMessageW(window, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(app->smallIcon));
        HWND list = GetDlgItem(window, IDC_FILES);
        ListView_SetExtendedListViewStyle(list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
        LVCOLUMNW column = {};
        column.mask = LVCF_TEXT | LVCF_WIDTH;
        column.pszText = const_cast<wchar_t*>(L"Файл"); column.cx = 210;
        ListView_InsertColumn(list, 0, &column);
        column.pszText = const_cast<wchar_t*>(L"Папка"); column.cx = 380;
        ListView_InsertColumn(list, 1, &column);
        SendDlgItemMessageW(window, IDC_LOCATION, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Текущий пользователь"));
        SendDlgItemMessageW(window, IDC_LOCATION, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Локальный компьютер — нужны права администратора"));
        SendDlgItemMessageW(window, IDC_LOCATION, CB_SETCURSEL, app->machine ? 1 : 0, 0);
        SendDlgItemMessageW(window, IDC_STORE, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Автоматически по типу сертификата"));
        SendDlgItemMessageW(window, IDC_STORE, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Все объекты → Доверенные корневые центры сертификации (Root)"));
        SendDlgItemMessageW(window, IDC_STORE, CB_SETCURSEL, app->root ? 1 : 0, 0);
        UpdateStoreHint(*app);
        SendDlgItemMessageW(window, IDC_LOG, EM_SETLIMITTEXT, 4000000, 0);
        app->logFont = CreateFontW(-MulDiv(9, app->dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                   DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                                   FIXED_PITCH | FF_MODERN, L"Consolas");
        if (app->logFont) SendDlgItemMessageW(window, IDC_LOG, WM_SETFONT, reinterpret_cast<WPARAM>(app->logFont), FALSE);
        DragAcceptFiles(window, TRUE);
        // Разрешаем только сообщения файлового drop для Explorer с обычными правами.
        ChangeWindowMessageFilterEx(window, WM_DROPFILES, MSGFLT_ALLOW, nullptr);
        ChangeWindowMessageFilterEx(window, WM_COPYGLOBALDATA_COMPAT, MSGFLT_ALLOW, nullptr);
        const auto selected = app->files;
        app->files.clear();
        for (const auto& path : selected) AddPath(*app, path);
        RefreshFiles(*app);
        // The requested width includes the frame; keep normal Windows DPI scaling.
        const int initialWidth = MulDiv(780, app->dpi, 96);
        RECT size = {0, 0, initialWidth, MulDiv(580, app->dpi, 96)};
        AdjustWindowRectEx(&size, static_cast<DWORD>(GetWindowLongPtrW(window, GWL_STYLE)), FALSE,
                           static_cast<DWORD>(GetWindowLongPtrW(window, GWL_EXSTYLE)));
        PositionInitialWindow(window, initialWidth, size.bottom - size.top);
        Layout(*app);
        if (app->startImport) PostMessageW(window, WM_START_IMPORT, 0, 0);
        if (app->smoke) PostMessageW(window, WM_UI_SMOKE, 0, 0);
        return TRUE;
    }
    if (!app) return FALSE;
    switch (message) {
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_ADD: if (!app->busy) ChooseFiles(*app); return TRUE;
        case IDC_REMOVE:
            if (!app->busy) {
                HWND list = GetDlgItem(window, IDC_FILES);
                for (int i = static_cast<int>(app->files.size()) - 1; i >= 0; --i)
                    if (ListView_GetItemState(list, i, LVIS_SELECTED)) app->files.erase(app->files.begin() + i);
                RefreshFiles(*app);
            }
            return TRUE;
        case IDC_CLEAR: if (!app->busy) { app->files.clear(); RefreshFiles(*app); } return TRUE;
        case IDC_INSTALL: StartImport(*app, false); return TRUE;
        case IDC_CHECK: StartImport(*app, true); return TRUE;
        case IDC_SAVELOG: SaveLog(*app); return TRUE;
        case IDC_LOCATION: if (HIWORD(wParam) == CBN_SELCHANGE) RefreshButtons(*app); return TRUE;
        case IDC_STORE:
            if (HIWORD(wParam) == CBN_SELCHANGE) UpdateStoreHint(*app);
            return TRUE;
        case IDCANCEL: SendMessageW(window, WM_CLOSE, 0, 0); return TRUE;
        }
        break;
    case WM_DROPFILES: DropFiles(*app, reinterpret_cast<HDROP>(wParam)); return TRUE;
    case WM_START_IMPORT: StartImport(*app, false); return TRUE;
    case WM_UI_SMOKE: SmokeStart(*app); return TRUE;
    case WM_PASSWORD_REQUEST: {
        auto request = reinterpret_cast<PasswordRequest*>(lParam);
        HINSTANCE instance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(window, GWLP_HINSTANCE));
        request->accepted = DialogBoxParamW(instance, MAKEINTRESOURCEW(IDD_PASSWORD), window,
            PasswordDialogProc, lParam) == IDOK;
        return TRUE;
    }
    case WM_LOG_LINE: {
        std::unique_ptr<std::wstring> line(reinterpret_cast<std::wstring*>(lParam));
        AppendLog(*app, *line);
        RefreshButtons(*app);
        return TRUE;
    }
    case WM_IMPORT_DONE: {
        std::unique_ptr<certinstaller::Summary> summary(reinterpret_cast<certinstaller::Summary*>(lParam));
        app->busy = false;
        std::wstring result = L"Установлено: " + Number(summary->installed) + L". Уже есть: " + Number(summary->skipped)
            + L". Ошибок: " + Number(summary->errors) + L". Проверено: " + Number(summary->planned)
            + L". Отменено файлов: " + Number(summary->cancelled) + L".";
        Status(*app, result);
        AppendLog(*app, L"Итог по объектам: " + result);
        RefreshButtons(*app);
        if (app->smoke) {
            if (summary->installed || summary->skipped || summary->errors || summary->cancelled || !summary->planned) app->exitCode = 2;
            DWORD error = 0;
            if (!WriteUtf8(app->smokeDirectory + L"\\gui-smoke.log", app->log, error)) app->exitCode = 2;
            // Задержка позволяет снять окно средствами автоматизированной проверки.
            SetTimer(window, 1, 3500, nullptr);
        }
        return TRUE;
    }
    case WM_TIMER: if (app->smoke && wParam == 1) { KillTimer(window, 1); DestroyWindow(window); return TRUE; } break;
    case WM_SIZE: if (wParam != SIZE_MINIMIZED) Layout(*app); return TRUE;
    case WM_GETMINMAXINFO: {
        auto info = reinterpret_cast<MINMAXINFO*>(lParam);
        info->ptMinTrackSize.x = MulDiv(650, app->dpi, 96);
        info->ptMinTrackSize.y = MulDiv(600, app->dpi, 96);
        return TRUE;
    }
    case WM_CLOSE:
        if (app->busy) { Status(*app, L"Дождитесь завершения обработки перед закрытием окна."); MessageBeep(MB_OK); }
        else DestroyWindow(window);
        return TRUE;
    case WM_DESTROY:
        if (app->logFont) { DeleteObject(app->logFont); app->logFont = nullptr; }
        PostQuitMessage(app->exitCode);
        return TRUE;
    }
    return FALSE;
}
} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    App app;
    int count = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &count);
    bool paths = false;
    if (arguments) {
        for (int i = 1; i < count; ++i) {
            const std::wstring argument = arguments[i];
            if (!paths && argument == L"--") paths = true;
            else if (!paths && argument == L"--machine") app.machine = true;
            else if (!paths && argument == L"--root") app.root = true;
            else if (!paths && argument == L"--install") app.startImport = true;
            else if (!paths && argument == L"--ui-smoke" && i + 1 < count) {
                app.smoke = true;
                app.smokeDirectory = FullPath(arguments[++i]);
            } else app.files.push_back(argument);
        }
        LocalFree(arguments);
    }
    INITCOMMONCONTROLSEX controls = {sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&controls);
    HWND window = CreateDialogParamW(instance, MAKEINTRESOURCEW(IDD_MAIN), nullptr, DialogProc, reinterpret_cast<LPARAM>(&app));
    if (!window) {
        MessageBoxW(nullptr, (L"Не удалось открыть окно. " + certinstaller::FormatWindowsError(GetLastError())).c_str(),
                    L"Установка сертификатов", MB_OK | MB_ICONERROR);
        return 1;
    }
    ShowWindow(window, show);
    UpdateWindow(window);
    MSG message = {};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(window, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
    }
    return static_cast<int>(message.wParam);
}
