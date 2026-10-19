
#define _WIN32_WINNT 0x0502
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

int main() {
    printf("Inspecting system environment...\n");
    
    // CPU & Memory checks
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        printf("Suspiciously low CPU count (< 2 cores).\n");
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
                    printf("Suspicious sandbox process name: %s\n", pe.szExeFile);
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    
    return 0;
}
