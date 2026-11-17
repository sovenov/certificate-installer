"""Developer GUI smoke test. Uses dry-run only; requires the adjacent Python test fixtures."""
import ctypes as ct
from ctypes import wintypes as wt
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import zlib

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from test_install_certificates import der, pem, pkcs7
from extended_test_fixtures import PFX_PASSWORD, PFX_EMPTY, TEST_PASSWORD

user32 = ct.WinDLL("user32", use_last_error=True)
gdi32 = ct.WinDLL("gdi32", use_last_error=True)

# Match the app's physical-pixel coordinates when comparing monitor/window rects.
def make_test_dpi_aware():
    try:
        set_thread = user32.SetThreadDpiAwarenessContext
        set_thread.argtypes = [ct.c_void_p]
        set_thread.restype = ct.c_void_p
        if set_thread(ct.c_void_p(-4)):  # Per-monitor v2, Windows 10+.
            return
    except AttributeError:
        pass
    try:
        shcore = ct.WinDLL("shcore", use_last_error=True)
        set_process = shcore.SetProcessDpiAwareness
        set_process.argtypes = [ct.c_int]
        set_process.restype = ct.c_long
        if set_process(2) == 0:  # Per-monitor, Windows 8.1+.
            return
    except (AttributeError, OSError):
        pass
    user32.SetProcessDPIAware()  # System-aware fallback, Windows 7.


make_test_dpi_aware()
user32.EnumWindows.argtypes = [ct.c_void_p, wt.LPARAM]
user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ct.POINTER(wt.DWORD)]
user32.IsWindowVisible.argtypes = [wt.HWND]
user32.IsWindowEnabled.argtypes = [wt.HWND]
user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.EnumChildWindows.argtypes = [wt.HWND, ct.c_void_p, wt.LPARAM]
user32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ct.c_int]
user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ct.c_int]
user32.GetWindowTextLengthW.argtypes = [wt.HWND]
user32.GetDlgCtrlID.argtypes = [wt.HWND]
user32.GetWindowRect.argtypes = [wt.HWND, ct.POINTER(wt.RECT)]
user32.GetWindowDC.argtypes = [wt.HWND]
user32.GetWindowDC.restype = wt.HDC
user32.ReleaseDC.argtypes = [wt.HWND, wt.HDC]
user32.PrintWindow.argtypes = [wt.HWND, wt.HDC, wt.UINT]
user32.GetDlgItem.argtypes = [wt.HWND, ct.c_int]
user32.GetDlgItem.restype = wt.HWND
user32.SendMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.SendMessageW.restype = ct.c_ssize_t
gdi32.CreateCompatibleDC.argtypes = [wt.HDC]
gdi32.CreateCompatibleDC.restype = wt.HDC
gdi32.CreateCompatibleBitmap.argtypes = [wt.HDC, ct.c_int, ct.c_int]
gdi32.CreateCompatibleBitmap.restype = wt.HBITMAP
gdi32.SelectObject.argtypes = [wt.HDC, wt.HGDIOBJ]
gdi32.SelectObject.restype = wt.HGDIOBJ
gdi32.GetDIBits.argtypes = [wt.HDC, wt.HBITMAP, wt.UINT, wt.UINT, ct.c_void_p, ct.c_void_p, wt.UINT]
gdi32.DeleteObject.argtypes = [wt.HGDIOBJ]
gdi32.DeleteDC.argtypes = [wt.HDC]
gdi32.BitBlt.argtypes = [wt.HDC, ct.c_int, ct.c_int, ct.c_int, ct.c_int,
                        wt.HDC, ct.c_int, ct.c_int, wt.DWORD]
gdi32.BitBlt.restype = wt.BOOL
user32.GetDC.argtypes = [wt.HWND]
user32.GetDC.restype = wt.HDC
user32.MonitorFromWindow.argtypes = [wt.HWND, wt.DWORD]
user32.MonitorFromWindow.restype = wt.HANDLE
user32.GetMonitorInfoW.argtypes = [wt.HANDLE, ct.c_void_p]
user32.GetMonitorInfoW.restype = wt.BOOL
gdi32.GetDeviceCaps.argtypes = [wt.HDC, ct.c_int]
gdi32.GetDeviceCaps.restype = ct.c_int


def process_windows(process_id):
    matches = []
    callback_type = ct.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    @callback_type
    def callback(window, _):
        owner = wt.DWORD()
        user32.GetWindowThreadProcessId(window, ct.byref(owner))
        if owner.value == process_id and user32.IsWindowVisible(window):
            matches.append(window)
        return True

    user32.EnumWindows(callback, 0)
    return matches


def get_window(process_id):
    matches = process_windows(process_id)
    return matches[0] if matches else None


def window_text(window):
    # WM_GETTEXT is marshalled by Windows for controls in this test's child process.
    length = user32.SendMessageW(window, 0x000E, 0, 0)
    buffer = ct.create_unicode_buffer(length + 1)
    user32.SendMessageW(window, 0x000D, len(buffer), ct.cast(buffer, ct.c_void_p).value)
    return buffer.value


def window_class(window):
    buffer = ct.create_unicode_buffer(128)
    user32.GetClassNameW(window, buffer, len(buffer))
    return buffer.value


def wait_for(condition, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = condition()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for GUI state")



class MonitorInfo(ct.Structure):
    _fields_ = [("cbSize", wt.DWORD), ("rcMonitor", wt.RECT),
                ("rcWork", wt.RECT), ("dwFlags", wt.DWORD)]


def window_rectangle(window):
    rectangle = wt.RECT()
    assert user32.GetWindowRect(window, ct.byref(rectangle)), "GetWindowRect failed"
    return rectangle.left, rectangle.top, rectangle.right, rectangle.bottom


def window_dpi(window):
    try:
        get_dpi = user32.GetDpiForWindow
        get_dpi.argtypes = [wt.HWND]
        get_dpi.restype = wt.UINT
        dpi = get_dpi(window)
        if dpi:
            return dpi
    except AttributeError:
        pass
    device = user32.GetDC(window)
    assert device, "GetDC failed while reading picker DPI"
    try:
        return gdi32.GetDeviceCaps(device, 88) or 96  # LOGPIXELSX.
    finally:
        user32.ReleaseDC(window, device)


def verify_picker_geometry(owner, dialog, screenshot_name="file-picker-preview.png"):
    monitor = user32.MonitorFromWindow(owner, 2)  # MONITOR_DEFAULTTONEAREST.
    info = MonitorInfo()
    info.cbSize = ct.sizeof(info)
    assert monitor and user32.GetMonitorInfoW(monitor, ct.byref(info)), "GetMonitorInfo failed"
    work = info.rcWork
    owner_left, owner_top, owner_right, owner_bottom = window_rectangle(owner)
    dpi = window_dpi(dialog)
    margin = (12*dpi + 48)//96
    available_left, available_top = max(owner_left, work.left), max(owner_top, work.top)
    available_right, available_bottom = min(owner_right, work.right), min(owner_bottom, work.bottom)
    expected_width = available_right-available_left-2*margin
    expected_height = available_bottom-available_top-2*margin
    assert expected_width > 0 and expected_height > 0, "No usable picker area inside owner/monitor"
    expected_left, expected_top = available_left+margin, available_top+margin
    expected = (expected_left, expected_top, expected_left+expected_width, expected_top+expected_height)
    latest = None
    matched_since = None

    def geometry_matches():
        nonlocal latest, matched_since
        latest = window_rectangle(dialog)
        left, top, right, bottom = latest
        size_matches = abs(right-left-expected_width) <= 2 and abs(bottom-top-expected_height) <= 2
        position_matches = abs(left-expected_left) <= 3 and abs(top-expected_top) <= 3
        inside_owner = (left >= owner_left and top >= owner_top and
                        right <= owner_right and bottom <= owner_bottom)
        fits_monitor = (left >= work.left and top >= work.top and
                        right <= work.right and bottom <= work.bottom)
        if not (size_matches and position_matches and inside_owner and fits_monitor):
            matched_since = None
            return False
        matched_since = matched_since or time.monotonic()
        return time.monotonic()-matched_since >= 0.15

    screenshot = ROOT / "build" / screenshot_name
    screenshot.parent.mkdir(exist_ok=True)
    try:
        wait_for(geometry_matches)
    except AssertionError:
        capture(dialog, screenshot)
        raise AssertionError("Picker geometry mismatch at {} DPI: actual {}, expected {}, owner {}, work {}".format(
            dpi, latest, expected, (owner_left, owner_top, owner_right, owner_bottom),
            (work.left, work.top, work.right, work.bottom))) from None
    get_style = getattr(user32, "GetWindowLongPtrW", user32.GetWindowLongW)
    get_style.argtypes = [wt.HWND, ct.c_int]
    get_style.restype = ct.c_ssize_t
    assert get_style(dialog, -16) & 0x00040000, "Native file picker must remain resizable"
    capture(dialog, screenshot)
    combined = screenshot.with_name(screenshot.stem + "-in-owner.png")
    capture(owner, combined, overlay=dialog)
    print("GUI PASS: file picker {}x{} at {} DPI; rect {}, {}px inset inside owner {}, monitor work {}.".format(
        latest[2]-latest[0], latest[3]-latest[1], dpi, latest, margin,
        (owner_left, owner_top, owner_right, owner_bottom),
        (work.left, work.top, work.right, work.bottom)))
    print("File picker screenshot:", screenshot)
    print("File picker inside owner screenshot:", combined)


def fill_file_dialog(process, main_window, button_id, filename, dialog_ready=None):
    user32.PostMessageW(main_window, 0x111, button_id, 0)
    dialog = wait_for(lambda: next((handle for handle in process_windows(process.pid)
                                   if handle != main_window and window_class(handle) == "#32770"), None))
    edits = []
    callback_type = ct.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    @callback_type
    def callback(window, _):
        name = ct.create_unicode_buffer(100)
        user32.GetClassNameW(window, name, len(name))
        if name.value == "Edit" and user32.GetDlgCtrlID(window) in {1148, 1001}:
            edits.append(window)
        return True

    def find_edits():
        edits.clear()
        user32.EnumChildWindows(dialog, callback, 0)
        return edits

    wait_for(find_edits)
    if dialog_ready:
        dialog_ready(dialog)
    if filename is None:  # A geometry-only check cancels without selecting files.
        user32.PostMessageW(dialog, 0x111, 2, 0)
        return
    text = ct.c_wchar_p(filename)
    assert user32.SendMessageW(edits[0], 0x000C, 0, ct.cast(text, ct.c_void_p).value)
    user32.PostMessageW(dialog, 0x111, 1, 0)



def reduced_owner_picker_test(process, window):
    dpi = window_dpi(window)
    target_width, target_height = (650*dpi+48)//96, (600*dpi+48)//96
    user32.SetWindowPos.argtypes = [wt.HWND, wt.HWND, ct.c_int, ct.c_int,
                                   ct.c_int, ct.c_int, wt.UINT]
    user32.SetWindowPos.restype = wt.BOOL
    # 650x600 logical is the main window minimum and remains above the native
    # picker minimum (observed width 625px at 96 DPI) after the 12px inset.
    assert user32.SetWindowPos(window, None, 0, 0, target_width, target_height, 0x16)

    def resized():
        left, top, right, bottom = window_rectangle(window)
        return abs(right-left-target_width) <= 2 and abs(bottom-top-target_height) <= 2

    wait_for(resized)
    fill_file_dialog(process, window, 1002, None,
                     dialog_ready=lambda dialog: verify_picker_geometry(
                         window, dialog, "file-picker-reduced-preview.png"))
    wait_for(lambda: user32.IsWindowEnabled(window))
    print("GUI PASS: manually reduced owner; native picker stays fully inside it and cancels cleanly.")


def picker_test():
    with tempfile.TemporaryDirectory(prefix="certificate-picker-") as directory:
        work = Path(directory)
        first, second = work / "Корневой сертификат.CeR", work / "Список отзыва.crl"
        first.write_bytes(der("ROOT"))
        second.write_bytes(der("CRL_OLD"))
        process = subprocess.Popen([str(ROOT / "dist/CertificateInstaller.exe")])
        try:
            window = wait_for(lambda: get_window(process.pid))
            listed = user32.GetDlgItem(window, 1001)
            fill_file_dialog(process, window, 1002, '"{}" "{}"'.format(first, second),
                             dialog_ready=lambda dialog: verify_picker_geometry(window, dialog))
            wait_for(lambda: user32.SendMessageW(listed, 0x1004, 0, 0) == 2)
            user32.PostMessageW(window, 0x111, 1008, 0)  # Check only, never Install.
            wait_for(lambda: "Проверено: 2." in window_text(user32.GetDlgItem(window, 1011)))
            log = window_text(user32.GetDlgItem(window, 1010))
            assert log.count("[ПЛАН]") == 2 and "[OK]" not in log and "[ОШИБКА]" not in log
            assert first.name in log, "Native picker did not accept the mixed-case CER filename"
            saved = work / "журнал импорта.log"
            fill_file_dialog(process, window, 1009, str(saved))
            wait_for(saved.exists)
            assert saved.read_bytes().decode("utf-8-sig") == log
            # Value-only list-view messages do not require remote pointer marshalling.
            user32.SendMessageW(listed, 0x100, 0x24, 0)  # WM_KEYDOWN, VK_HOME.
            assert user32.SendMessageW(listed, 0x1032, 0, 0) == 1, "Row selection failed"
            user32.PostMessageW(window, 0x111, 1003, 0)
            wait_for(lambda: user32.SendMessageW(listed, 0x1004, 0, 0) == 1)
            user32.PostMessageW(window, 0x111, 1004, 0)
            wait_for(lambda: user32.SendMessageW(listed, 0x1004, 0, 0) == 0)
            assert not user32.IsWindowEnabled(user32.GetDlgItem(window, 1007))
            assert not user32.IsWindowEnabled(user32.GetDlgItem(window, 1008))
            reduced_owner_picker_test(process, window)
            user32.PostMessageW(window, 0x10, 0, 0)
            assert process.wait(timeout=5) == 0
            print("GUI PASS: native multi-file picker, Unicode/mixed-case CER paths, automatic/user dry-run, save-log dialog, remove selection, clear list, disabled empty actions.")
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


def serialized_store_fixture():
    """Return an SST containing a cert and CRL; all native work stays in MEMORY."""
    crypt32 = ct.WinDLL("crypt32", use_last_error=True)

    class Blob(ct.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ct.POINTER(ct.c_ubyte))]

    crypt32.CertOpenStore.argtypes = [ct.c_void_p, wt.DWORD, ct.c_void_p,
                                    wt.DWORD, ct.c_void_p]
    crypt32.CertOpenStore.restype = wt.HANDLE
    crypt32.CertCloseStore.argtypes = [wt.HANDLE, wt.DWORD]
    crypt32.CertCloseStore.restype = wt.BOOL
    crypt32.CertSaveStore.argtypes = [wt.HANDLE, wt.DWORD, wt.DWORD, wt.DWORD,
                                    ct.c_void_p, wt.DWORD]
    crypt32.CertSaveStore.restype = wt.BOOL
    store = crypt32.CertOpenStore(ct.c_void_p(2), 0, None, 0, None)  # MEMORY only.
    assert store, "Could not create disposable SST fixture store"
    try:
        for function_name, payload in (("CertAddEncodedCertificateToStore", der("ROOT")),
                                       ("CertAddEncodedCRLToStore", der("CRL_OLD"))):
            add = getattr(crypt32, function_name)
            add.argtypes = [wt.HANDLE, wt.DWORD, ct.c_void_p, wt.DWORD,
                            wt.DWORD, ct.c_void_p]
            add.restype = wt.BOOL
            data = ct.create_string_buffer(payload)
            assert add(store, 1, data, len(payload), 4, None), "Could not populate SST fixture"
        blob = Blob()
        # SAVE_AS_STORE=1, SAVE_TO_MEMORY=2; neither call writes a system store.
        assert crypt32.CertSaveStore(store, 0x10001, 1, 2, ct.byref(blob), 0)
        data = (ct.c_ubyte * blob.cbData)()
        blob.pbData = data
        assert crypt32.CertSaveStore(store, 0x10001, 1, 2, ct.byref(blob), 0)
        return bytes(data[:blob.cbData])
    finally:
        assert crypt32.CertCloseStore(store, 0), "Could not close disposable SST fixture store"


def extended_picker_files(work):
    """Seven selected files, fourteen planned objects, one file-only cancel."""
    fixtures = [
        ("01_Набор сертификатов.PeM", pem("ROOT") + pem("LEAF") + pem("CRL_OLD"), 3),
        ("02_Корневой сертификат.DeR", der("ROOT"), 1),
        ("03_Цепочка сертификатов.P7C", pkcs7(), 4),
        ("04_Хранилище сертификатов.SsT", serialized_store_fixture(), 2),
        ("05_Защищенный контейнер.PfX", PFX_PASSWORD, 2),
        ("06_Пропустить контейнер.PFX", PFX_PASSWORD, 0),
        ("07_Без пароля.P12", PFX_EMPTY, 2),
    ]
    selected = []
    for name, payload, planned in fixtures:
        path = work / name
        path.write_bytes(payload)
        selected.append((path, planned))
    return selected


PASSWORD_RETRY_HINT = (
    "Не удалось открыть контейнер с этим паролем. Повторите ввод или пропустите файл."
)


def wait_for_password_dialog(process, filename, retry=False):
    def find_dialog():
        for window in process_windows(process.pid):
            if window_class(window) != "#32770" or window_text(window) != "Пароль PFX/P12":
                continue
            if window_text(user32.GetDlgItem(window, 1016)) != str(filename):
                continue
            hint = window_text(user32.GetDlgItem(window, 1017))
            if (hint == PASSWORD_RETRY_HINT) == retry:
                return window
        return None

    dialog = wait_for(find_dialog)
    path_edit = user32.GetDlgItem(dialog, 1016)
    password_edit = user32.GetDlgItem(dialog, 1018)
    assert path_edit and password_edit, "Password dialog controls are missing"
    get_style = getattr(user32, "GetWindowLongPtrW", user32.GetWindowLongW)
    get_style.argtypes = [wt.HWND, ct.c_int]
    get_style.restype = ct.c_ssize_t
    assert get_style(path_edit, -16) & 0x0800, "PFX filename must be read-only"
    assert get_style(password_edit, -16) & 0x0020, "PFX password edit must use ES_PASSWORD"
    assert user32.SendMessageW(password_edit, 0x00D2, 0, 0), "PFX password masking is disabled"
    assert user32.SendMessageW(password_edit, 0x000E, 0, 0) == 0, "Password edit was not cleared"
    assert window_text(user32.GetDlgItem(dialog, 2)) == "Пропустить файл"
    return dialog


def submit_password(dialog, password):
    text = ct.c_wchar_p(password)
    edit = user32.GetDlgItem(dialog, 1018)
    assert user32.SendMessageW(edit, 0x000C, 0, ct.cast(text, ct.c_void_p).value)
    user32.PostMessageW(dialog, 0x111, 1, 0)


def extended_picker_test():
    with tempfile.TemporaryDirectory(prefix="certificate-extended-picker-") as directory:
        work = Path(directory)
        files = extended_picker_files(work)
        process = subprocess.Popen([str(ROOT / "dist/CertificateInstaller.exe")])
        try:
            window = wait_for(lambda: get_window(process.pid))
            listed = user32.GetDlgItem(window, 1001)
            selection = " ".join('"{}"'.format(path) for path, _ in files)
            fill_file_dialog(process, window, 1002, selection)
            wait_for(lambda: user32.SendMessageW(listed, 0x1004, 0, 0) == len(files))
            # This is deliberately Check (1008), never Install (1007).
            user32.PostMessageW(window, 0x111, 1008, 0)
            protected = files[4][0]
            cancelled = files[5][0]
            empty_password = files[6][0]
            first_dialog = wait_for_password_dialog(process, protected)
            capture(first_dialog, ROOT / "build/password-dialog-preview.png")
            wrong_password = "Wrong-GUI-Test-Password-Do-Not-Log"
            submit_password(first_dialog, wrong_password)
            retry_dialog = wait_for_password_dialog(process, protected, retry=True)
            submit_password(retry_dialog, TEST_PASSWORD)
            cancel_dialog = wait_for_password_dialog(process, cancelled)
            user32.PostMessageW(cancel_dialog, 0x111, 2, 0)
            status_control = user32.GetDlgItem(window, 1011)
            wait_for(lambda: "Проверено: 14." in window_text(status_control), timeout=15)
            status = window_text(status_control)
            assert "Отменено файлов: 1." in status and "Ошибок: 0." in status, status
            log = window_text(user32.GetDlgItem(window, 1010))
            plans = [line for line in log.splitlines() if line.startswith("[ПЛАН]")]
            assert len(plans) == 14, "Expected fourteen dry-run objects across seven selected files"
            assert "[OK]" not in log and "[ОШИБКА]" not in log, "Extended check failed or changed stores"
            for path, planned in files:
                assert sum(path.name in line for line in plans) == planned, (
                    "Wrong dry-run object count for " + path.name)
            assert empty_password.name in plans[-1], "Processing did not continue after cancelling one PFX"
            assert TEST_PASSWORD not in log and wrong_password not in log, "Password leaked to GUI log"
            saved = work / "журнал новых форматов.log"
            fill_file_dialog(process, window, 1009, str(saved))
            wait_for(saved.exists)
            saved_log = saved.read_bytes().decode("utf-8-sig")
            assert saved_log == log, "Saved extended-format log differs from GUI log"
            assert TEST_PASSWORD not in saved_log and wrong_password not in saved_log, "Password leaked to saved log"
            capture(window, ROOT / "build/extended-formats-preview.png")
            (ROOT / "build/extended-formats-smoke.log").write_text(log, encoding="utf-8")
            user32.PostMessageW(window, 0x10, 0, 0)
            assert process.wait(timeout=5) == 0
            print("GUI PASS: native picker accepts mixed-case PEM/DER/P7C/SST/PFX/P12; seven files, fourteen dry-run objects, masked password, wrong-password retry, one-file cancel with continuation, password-free displayed/saved logs, clean exit.")
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)



def paint_overlay(memory, owner_rectangle, window):
    """Compose only our two PrintWindow images; no desktop pixels are captured."""
    rectangle = wt.RECT()
    assert user32.GetWindowRect(window, ct.byref(rectangle))
    width, height = rectangle.right-rectangle.left, rectangle.bottom-rectangle.top
    screen = user32.GetWindowDC(window)
    overlay_dc = gdi32.CreateCompatibleDC(screen)
    bitmap = gdi32.CreateCompatibleBitmap(screen, width, height)
    previous = gdi32.SelectObject(overlay_dc, bitmap)
    try:
        assert user32.PrintWindow(window, overlay_dc, 0), "Overlay PrintWindow failed"
        assert gdi32.BitBlt(memory, rectangle.left-owner_rectangle.left,
                           rectangle.top-owner_rectangle.top, width, height,
                           overlay_dc, 0, 0, 0x00CC0020), "Overlay BitBlt failed"
    finally:
        gdi32.SelectObject(overlay_dc, previous)
        gdi32.DeleteObject(bitmap)
        gdi32.DeleteDC(overlay_dc)
        user32.ReleaseDC(window, screen)


def capture(window, destination, overlay=None):
    rectangle = wt.RECT()
    assert user32.GetWindowRect(window, ct.byref(rectangle))
    width, height = rectangle.right - rectangle.left, rectangle.bottom - rectangle.top
    screen = user32.GetWindowDC(window)
    memory = gdi32.CreateCompatibleDC(screen)
    bitmap = gdi32.CreateCompatibleBitmap(screen, width, height)
    previous = gdi32.SelectObject(memory, bitmap)
    try:
        assert user32.PrintWindow(window, memory, 0), "PrintWindow failed"
        if overlay:
            paint_overlay(memory, rectangle, overlay)
        gdi32.SelectObject(memory, previous)
        previous = None
        bitmap_info = ct.create_string_buffer(40)
        struct.pack_into("<IiiHHIIiiII", bitmap_info, 0, 40, width, -height, 1, 32, 0, width * height * 4, 0, 0, 0, 0)
        pixels = ct.create_string_buffer(width * height * 4)
        assert gdi32.GetDIBits(memory, bitmap, 0, height, pixels, bitmap_info, 0) == height
        raw = pixels.raw
        rows = bytearray()
        for y in range(height):
            rows.append(0)
            line = raw[y * width * 4:(y + 1) * width * 4]
            for x in range(0, len(line), 4):
                rows.extend((line[x + 2], line[x + 1], line[x]))

        def chunk(name, value):
            return struct.pack(">I", len(value)) + name + value + struct.pack(">I", zlib.crc32(name + value) & 0xFFFFFFFF)

        destination.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
                                + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))
    finally:
        if previous:
            gdi32.SelectObject(memory, previous)
        gdi32.DeleteObject(bitmap)
        gdi32.DeleteDC(memory)
        user32.ReleaseDC(window, screen)


def main():
    (ROOT / "build").mkdir(exist_ok=True)
    executable = ROOT / "dist/CertificateInstaller.exe"
    screenshot = ROOT / "build/gui-preview.png"
    with tempfile.TemporaryDirectory(prefix="certificate-gui-") as directory:
        work = Path(directory)
        (work / "root.CeR").write_bytes(der("ROOT"))
        (work / "leaf.cer").write_bytes(pem("LEAF"))
        (work / "revocations.crl").write_bytes(der("CRL_OLD"))
        (work / "chain.p7b").write_bytes(pkcs7())
        process = subprocess.Popen([str(executable), "--ui-smoke", str(work)])
        try:
            window = None
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and process.poll() is None:
                window = get_window(process.pid)
                if window and (work / "gui-smoke.log").exists():
                    break
                time.sleep(0.05)
            assert window and (work / "gui-smoke.log").exists(), "GUI did not finish dry-run"
            assert user32.SendMessageW(user32.GetDlgItem(window, 1001), 0x1004, 0, 0) == 4, "File list/drop/dedup failed"
            assert user32.SendMessageW(user32.GetDlgItem(window, 1005), 0x147, 0, 0) == 1, "Location selection lost"
            assert user32.SendMessageW(user32.GetDlgItem(window, 1006), 0x147, 0, 0) == 1, "Store selection lost"
            capture(window, screenshot)
            result = process.wait(timeout=15)
            log = (work / "gui-smoke.log").read_text(encoding="utf-8-sig")
            (ROOT / "build/gui-smoke.log").write_text(log, encoding="utf-8")
            assert result == 0, "GUI smoke returned {}".format(result)
            assert log.count("[ПЛАН]") == 7, "Expected all 7 objects from 4 input files"
            assert "[ОШИБКА]" not in log and "[OK]" not in log, "Dry-run changed stores or failed"
            assert "root.CeR" in log and "leaf.cer" in log, "Drop did not accept DER and PEM CER fixtures"
            print("GUI PASS: drag/drop with DER/PEM CER paths, four-file list, deduplication, location/store choices, seven dry-run objects, log, clean exit.")
            print("Screenshot:", screenshot)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
    picker_test()
    extended_picker_test()


if __name__ == "__main__":
    main()
