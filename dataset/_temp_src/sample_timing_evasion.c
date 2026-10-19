
#define _WIN32_WINNT 0x0502
#include <windows.h>
#include <stdio.h>

int main() {
    printf("Evaluating execution timing metrics...\n");
    
    DWORD tickStart = GetTickCount();
    
    LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    
    // Delay / sleep evasion
    Sleep(2000);
    
    QueryPerformanceCounter(&t2);
    DWORD tickEnd = GetTickCount();
    
    if ((tickEnd - tickStart) < 1800) {
        printf("Sandbox timing acceleration detected! Fast-forwarding sleep.\n");
        return 1;
    }
    
    printf("Elapsed: %lu ms\n", (tickEnd - tickStart));
    return 0;
}
