
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
    const char* vm_reg = "HARDWARE\\DEVICEMAP\\Scsi";
    const char* vbox_drv = "VBoxMouse.sys";
    const char* tool = "x64dbg";
    const char* net_mac = "08:00:27:00:00:00";
    printf("Scanning: %s, %s, %s, %s\n", vm_reg, vbox_drv, tool, net_mac);

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
