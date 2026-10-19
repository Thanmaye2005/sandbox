
#define _WIN32_WINNT 0x0502
#include <windows.h>
#include <stdio.h>

int main() {
    printf("Performing environment integrity scan...\n");

    // Device / driver string artifacts
    const char* vm_artifacts[] = {
        "VBoxGuestAdditions",
        "VBoxMouse.sys",
        "vmtoolsd.exe",
        "vmmouse.sys",
        "QEMU HARDDISK",
        "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        "00:05:69:AA:BB:CC",
        "08:00:27:11:22:33"
    };

    // Sandbox and environment strings
    const char* sandbox_markers = "C:\\agent\\agent.py";
    printf("Checking virtual machine signatures: %s, %s, %s\n", vm_artifacts[0], vm_artifacts[2], sandbox_markers);

    ULARGE_INTEGER freeBytes, totalBytes, totalFree;
    GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, &totalFree);
    
    return 0;
}
