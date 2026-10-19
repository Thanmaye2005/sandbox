"""Dataset Preparation Script
Compiles genuine benign and suspicious PE test executables and collects benign system samples.
"""

import os
import shutil
import subprocess
import struct
import pefile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
BENIGN_DIR = os.path.join(DATASET_DIR, "benign")
SUSPICIOUS_DIR = os.path.join(DATASET_DIR, "suspicious")
TEMP_SRC_DIR = os.path.join(DATASET_DIR, "_temp_src")

os.makedirs(BENIGN_DIR, exist_ok=True)
os.makedirs(SUSPICIOUS_DIR, exist_ok=True)
os.makedirs(TEMP_SRC_DIR, exist_ok=True)


def copy_benign_system_samples():
    """Copy standard benign Windows binaries to benign dataset directory."""
    system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    samples = ["attrib.exe", "ping.exe", "whoami.exe"]
    for s in samples:
        src = os.path.join(system32, s)
        dst = os.path.join(BENIGN_DIR, s)
        if os.path.exists(src):
            shutil.copy2(src, dst)
            print(f"[+] Copied benign system sample: {dst}")


SAMPLE_SOURCES = {
    # 1. Clean Benign Sample
    "benign_hello.c": """
#define _WIN32_WINNT 0x0502
#include <windows.h>
#include <stdio.h>

int main() {
    printf("Hello from a benign utility program.\\n");
    return 0;
}
""",

    # 2. Anti-Debug Sample
    "sample_anti_debug.c": """
#define _WIN32_WINNT 0x0502
#include <windows.h>
#include <stdio.h>

int main() {
    printf("Initializing protection mechanisms...\\n");
    
    // Static API import hits
    if (IsDebuggerPresent()) {
        printf("Debugger detected via IsDebuggerPresent!\\n");
        return 1;
    }
    
    BOOL isDebugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugger);
    if (isDebugger) {
        printf("Debugger detected via CheckRemoteDebuggerPresent!\\n");
        return 1;
    }
    
    OutputDebugStringA("Checking debugger presence...\\n");

    // Suspicious analysis tool strings
    const char* dbg_tools[] = {
        "x64dbg",
        "ollydbg",
        "ida.exe",
        "Wireshark",
        "Process Hacker"
    };
    for (int i = 0; i < 5; i++) {
        if (FindWindowA(NULL, dbg_tools[i])) {
            printf("Found analysis tool: %s\\n", dbg_tools[i]);
            return 1;
        }
    }
    
    return 0;
}
""",

    # 3. Anti-VM / Hypervisor Sample
    "sample_anti_vm.c": """
#define _WIN32_WINNT 0x0502
#include <windows.h>
#include <stdio.h>

int main() {
    printf("Performing environment integrity scan...\\n");

    // Device / driver string artifacts
    const char* vm_artifacts[] = {
        "VBoxGuestAdditions",
        "VBoxMouse.sys",
        "vmtoolsd.exe",
        "vmmouse.sys",
        "QEMU HARDDISK",
        "HARDWARE\\\\DEVICEMAP\\\\Scsi\\\\Scsi Port 0\\\\Scsi Bus 0\\\\Target Id 0\\\\Logical Unit Id 0",
        "00:05:69:AA:BB:CC",
        "08:00:27:11:22:33"
    };

    // Sandbox and environment strings
    const char* sandbox_markers = "C:\\\\agent\\\\agent.py";
    printf("Checking virtual machine signatures: %s, %s, %s\\n", vm_artifacts[0], vm_artifacts[2], sandbox_markers);

    ULARGE_INTEGER freeBytes, totalBytes, totalFree;
    GetDiskFreeSpaceExA("C:\\\\", &freeBytes, &totalBytes, &totalFree);
    
    return 0;
}
""",

    # 4. Timing Evasion Sample
    "sample_timing_evasion.c": """
#define _WIN32_WINNT 0x0502
#include <windows.h>
#include <stdio.h>

int main() {
    printf("Evaluating execution timing metrics...\\n");
    
    DWORD tickStart = GetTickCount();
    
    LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    
    // Delay / sleep evasion
    Sleep(2000);
    
    QueryPerformanceCounter(&t2);
    DWORD tickEnd = GetTickCount();
    
    if ((tickEnd - tickStart) < 1800) {
        printf("Sandbox timing acceleration detected! Fast-forwarding sleep.\\n");
        return 1;
    }
    
    printf("Elapsed: %lu ms\\n", (tickEnd - tickStart));
    return 0;
}
""",

    # 5. Environment Fingerprinting Sample
    "sample_env_checks.c": """
#define _WIN32_WINNT 0x0502
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

int main() {
    printf("Inspecting system environment...\\n");
    
    // CPU & Memory checks
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        printf("Suspiciously low CPU count (< 2 cores).\\n");
    }
    
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    
    // Process enumeration check
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (strstr(pe.szExeFile, "sample") || strstr(pe.szExeFile, "sandbox")) {
                    printf("Suspicious sandbox process name: %s\\n", pe.szExeFile);
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    
    return 0;
}
""",

    # 6. Multi-Evasion Sample
    "sample_multi_evasion.c": """
#define _WIN32_WINNT 0x0502
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

int main() {
    // Debugger check
    if (IsDebuggerPresent()) return 1;
    BOOL isDbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDbg);
    OutputDebugStringA("Checking debugger...");

    // VM indicators & strings
    const char* vm_reg = "HARDWARE\\\\DEVICEMAP\\\\Scsi";
    const char* vbox_drv = "VBoxMouse.sys";
    const char* tool = "x64dbg";
    const char* net_mac = "08:00:27:00:00:00";
    printf("Scanning: %s, %s, %s, %s\\n", vm_reg, vbox_drv, tool, net_mac);

    // Environment & hardware checks
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) CloseHandle(snap);

    // Timing check
    DWORD t1 = GetTickCount();
    Sleep(1000);
    DWORD t2 = GetTickCount();
    if (t2 - t1 < 800) return 1;

    return 0;
}
"""
}


def compile_test_samples():
    """Compile test samples using gcc with Windows headers."""
    for filename, code in SAMPLE_SOURCES.items():
        c_path = os.path.join(TEMP_SRC_DIR, filename)
        exe_name = os.path.splitext(filename)[0] + ".exe"
        if filename.startswith("benign"):
            out_exe = os.path.join(BENIGN_DIR, exe_name)
        else:
            out_exe = os.path.join(SUSPICIOUS_DIR, exe_name)

        with open(c_path, "w", encoding="utf-8") as f:
            f.write(code)

        cmd = ["gcc", "-D_WIN32_WINNT=0x0502", c_path, "-o", out_exe]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print(f"[+] Compiled successfully: {out_exe}")
        else:
            print(f"[-] Failed to compile {filename}: {res.stderr}")


def create_packed_entropy_sample():
    """Create a high-entropy / packed sample with a .upx1 section."""
    base_exe = os.path.join(SUSPICIOUS_DIR, "sample_anti_vm.exe")
    out_exe = os.path.join(SUSPICIOUS_DIR, "sample_packed_crypt.exe")
    if not os.path.exists(base_exe):
        return

    # Read base PE
    with open(base_exe, "rb") as f:
        data = bytearray(f.read())

    # We append a simulated packed section payload (random bytes) and string markers
    packed_strings = b"\x00\x00.upx0\x00\x00.upx1\x00UPX! encrypted payload\x00"
    random_bytes = os.urandom(8192)  # High entropy (approx 7.99)
    data.extend(packed_strings + random_bytes)

    with open(out_exe, "wb") as f:
        f.write(data)
    print(f"[+] Created packed / high-entropy sample: {out_exe}")


if __name__ == "__main__":
    print("Preparing dataset samples...")
    copy_benign_system_samples()
    compile_test_samples()
    create_packed_entropy_sample()
    print("Dataset preparation complete.")
