
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

/* NON-MALICIOUS controlled anti-analysis test binary */

static const char* g_vm_strings[] = {
    "VBoxGuestAdditions", "vmtoolsd.exe", "QEMU HARDDISK",
    "C:\\agent\\agent.py", "00:05:69:AA:BB:CC", "08:00:27:00:00:00",
    "vmmouse.sys", "VBoxMouse.sys", NULL
};
static const char* g_dbg_strings[] = {
    "ollydbg", "x64dbg", "ida.exe", "Wireshark", "Process Hacker", NULL
};

BOOL check_debugger(void) {
    if (IsDebuggerPresent()) return TRUE;
    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    return remote;
}

void timing_check(void) {
    LARGE_INTEGER t1, t2, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    Sleep(1);
    QueryPerformanceCounter(&t2);
    DWORD tick = GetTickCount();
    (void)tick;
}

BOOL environment_check(void) {
    MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                for (int i = 0; g_dbg_strings[i]; i++)
                    if (_stricmp(pe.szExeFile, g_dbg_strings[i]) == 0) {
                        CloseHandle(snap); return TRUE;
                    }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    return FALSE;
}

int main(void) {
    printf("[SAMPLE] Controlled anti-analysis test binary\n");
    if (check_debugger()) { printf("[SAMPLE] Debugger detected.\n"); return 1; }
    timing_check();
    if (environment_check()) { printf("[SAMPLE] Analysis env detected.\n"); return 2; }
    volatile const char** vm = (volatile const char**)g_vm_strings; (void)vm;
    void* buf = VirtualAlloc(NULL, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (buf) VirtualFree(buf, 0, MEM_RELEASE);
    printf("[SAMPLE] Done.\n");
    return 0;
}
