
#define _WIN32_WINNT 0x0502
#include <windows.h>
#include <stdio.h>

int main() {
    printf("Initializing protection mechanisms...\n");
    
    // Static API import hits
    if (IsDebuggerPresent()) {
        printf("Debugger detected via IsDebuggerPresent!\n");
        return 1;
    }
    
    BOOL isDebugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugger);
    if (isDebugger) {
        printf("Debugger detected via CheckRemoteDebuggerPresent!\n");
        return 1;
    }
    
    OutputDebugStringA("Checking debugger presence...\n");

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
            printf("Found analysis tool: %s\n", dbg_tools[i]);
            return 1;
        }
    }
    
    return 0;
}
