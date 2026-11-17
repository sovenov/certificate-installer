"""Developer build only. The resulting EXE needs neither Python nor MSVC installed."""
import argparse
import ctypes
import os
from pathlib import Path
import re
import struct
import subprocess
import sys


ROOT = Path(__file__).resolve().parent


def run(arguments, environment):
    subprocess.run([str(value) for value in arguments], cwd=ROOT, env=environment, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--msvc", type=Path, help="VC/Tools/MSVC/<version> directory")
    parser.add_argument("--sdk", default="10.0.22621.0", help="Windows SDK version")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Build on Windows using MSVC v142/v143 and the Windows SDK.")
    tools = args.msvc
    if tools is None:
        candidates = []
        for variable in ("ProgramFiles(x86)", "ProgramFiles"):
            base = Path(os.environ.get(variable, "C:/Program Files")) / "Microsoft Visual Studio"
            for candidate in base.glob("*/*/VC/Tools/MSVC/*"):
                version = tuple(int(value) for value in candidate.name.split(".") if value.isdigit())
                if (14, 20) <= version < (14, 50) and (candidate / "bin/Hostx64/x86/cl.exe").is_file():
                    candidates.append((version, candidate))
        if not candidates:
            parser.error("MSVC v142/v143 not found. Use --msvc with a VS2019/2022 toolset; VS2026 v145 targets Windows10+.")
        tools = max(candidates)[1]
    version = tuple(int(value) for value in tools.name.split(".") if value.isdigit())
    if not ((14, 20) <= version < (14, 50)):
        parser.error("Windows7 build requires a v142/v143 toolset (14.2x-14.4x), not v145.")
    sdk = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Windows Kits/10"
    compiler = tools / "bin/Hostx64/x86"
    resource_compiler = sdk / "bin" / args.sdk / "x86/rc.exe"
    if not resource_compiler.is_file():
        parser.error("Windows SDK {} not found; specify the installed version using --sdk.".format(args.sdk))
    environment = os.environ.copy()
    environment["PATH"] = str(compiler) + os.pathsep + environment.get("PATH", "")
    environment["INCLUDE"] = os.pathsep.join(str(value) for value in [
        tools / "include", sdk / "Include" / args.sdk / "ucrt",
        sdk / "Include" / args.sdk / "shared", sdk / "Include" / args.sdk / "um",
    ])
    environment["LIB"] = os.pathsep.join(str(value) for value in [
        tools / "lib/x86", sdk / "Lib" / args.sdk / "ucrt/x86", sdk / "Lib" / args.sdk / "um/x86",
    ])
    environment["VSLANG"] = "1033"
    (ROOT / "build").mkdir(exist_ok=True)
    (ROOT / "dist").mkdir(exist_ok=True)
    print("Compiler:", tools, flush=True)
    print("SDK:", args.sdk, flush=True)
    common = ["/nologo", "/std:c++14", "/utf-8", "/W4", "/EHsc", "/MT", "/O2",
              "/DUNICODE", "/D_UNICODE", "/DWINVER=0x0601", "/D_WIN32_WINNT=0x0601",
              "/DNOMINMAX", "/Fobuild/"]
    run([resource_compiler, "/nologo", "/fo", "build/app.res", "app.rc"], environment)
    run([compiler / "cl.exe", *common, "main.cpp", "certificate_import.cpp", "build/app.res",
         "/Fedist/CertificateInstaller.exe", "/link", "/SUBSYSTEM:WINDOWS,6.01", "/MANIFEST:NO",
         "comctl32.lib", "comdlg32.lib", "shell32.lib", "user32.lib", "gdi32.lib",
         "advapi32.lib", "crypt32.lib"], environment)
    run([compiler / "cl.exe", *common, "tests.cpp", "certificate_import.cpp",
         "/Febuild/certificate_import_tests.exe", "/link", "/SUBSYSTEM:CONSOLE,6.01",
         "advapi32.lib", "crypt32.lib"], environment)
    run([ROOT / "build/certificate_import_tests.exe"], environment)
    executable = ROOT / "dist/CertificateInstaller.exe"
    audit = subprocess.check_output([str(compiler / "dumpbin.exe"), "/headers", "/imports", "/dependents",
                                     str(executable)], env=environment, cwd=ROOT).decode("utf-8", errors="replace")
    (ROOT / "build/pe-audit.txt").write_text(audit, encoding="utf-8")
    libraries = set(re.findall(r"^\s*([A-Za-z0-9_.-]+\.dll)\s*$", audit, re.MULTILINE | re.IGNORECASE))
    allowed = {"kernel32.dll", "user32.dll", "gdi32.dll", "shell32.dll", "comdlg32.dll",
               "comctl32.dll", "crypt32.dll", "advapi32.dll"}
    unexpected = {value for value in libraries if value.lower() not in allowed}
    if unexpected:
        raise RuntimeError("Unexpected DLL dependencies: " + ", ".join(sorted(unexpected)))
    for name in ("WaitOnAddress", "GetDpiForWindow", "GetSystemTimePreciseAsFileTime", "GetOverlappedResultEx"):
        if re.search(r"\b" + name + r"\b", audit):
            raise RuntimeError("Windows8+ import found: " + name)
    binary = executable.read_bytes()
    pe_offset = struct.unpack_from("<I", binary, 0x3C)[0]
    optional = pe_offset + 24
    assert binary[pe_offset:pe_offset + 4] == b"PE\0\0"
    assert struct.unpack_from("<H", binary, pe_offset + 4)[0] == 0x14C, "Expected x86"
    assert struct.unpack_from("<H", binary, optional)[0] == 0x10B, "Expected PE32"
    assert struct.unpack_from("<HH", binary, optional + 48) == (6, 1), "Expected Windows7 subsystem"
    assert struct.unpack_from("<H", binary, optional + 68)[0] == 2, "Expected Windows GUI"
    assert struct.unpack_from("<II", binary, optional + 96 + 14 * 8) == (0, 0), "Unexpected CLR"
    print("PE audit passed: x86, Windows6.1 GUI, native, system DLLs only.")
    # Refresh Explorer's cached icon for the single output executable.
    notify = ctypes.WinDLL("shell32").SHChangeNotify
    notify.argtypes = [ctypes.c_long, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
    notify.restype = None
    notify(0x00002000, 0x0005 | 0x1000,
           ctypes.cast(ctypes.c_wchar_p(str(executable)), ctypes.c_void_p), None)
    print("Built:", executable)


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError, RuntimeError, AssertionError) as error:
        print("Build failed:", error, file=sys.stderr)
        sys.exit(1)
