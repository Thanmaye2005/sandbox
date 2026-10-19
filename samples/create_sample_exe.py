"""
create_sample_exe.py
Build a controlled 'sample.exe' test PE file that intentionally demonstrates:
  - Anti-debugging APIs (IsDebuggerPresent, CheckRemoteDebuggerPresent)
  - VM-detection strings (VBoxGuestAdditions, vmtoolsd.exe, QEMU HARDDISK)
  - Timing evasion APIs (Sleep, QueryPerformanceCounter, GetTickCount)
  - Environment checks (CreateToolhelp32Snapshot, GlobalMemoryStatusEx)
  - Suspicious strings (ollydbg, x64dbg, wireshark)
  - Suspicious memory API (VirtualAlloc)

Compile path: tries gcc (MinGW) first; falls back to a hand-crafted PE stub.
"""

import os
import sys
import subprocess
import struct
import hashlib

SAMPLE_C_SOURCE = r"""
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
"""

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_C_PATH  = os.path.join(HERE, "_sample_src.c")
SAMPLE_EXE_PATH = os.path.join(HERE, "sample.exe")


# ---------------------------------------------------------------------------
# GCC compile path
# ---------------------------------------------------------------------------
def try_compile_gcc() -> bool:
    for gcc in ["gcc", "x86_64-w64-mingw32-gcc", "i686-w64-mingw32-gcc"]:
        try:
            r = subprocess.run(
                [gcc, SAMPLE_C_PATH, "-o", SAMPLE_EXE_PATH,
                 "-lkernel32", "-lpsapi", "-mconsole",
                 "-static-libgcc", "-static"],
                capture_output=True, text=True, timeout=60
            )
            if r.returncode == 0 and os.path.isfile(SAMPLE_EXE_PATH):
                print(f"[+] Compiled with {gcc}")
                return True
            print(f"[~] {gcc}: {r.stderr.strip()[:200]}")
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[~] {gcc}: {e}")
    return False


# ---------------------------------------------------------------------------
# PE stub builder — produces a valid 32-bit PE with import table
# ---------------------------------------------------------------------------
def build_stub_pe() -> bytes:
    """
    Hand-craft a minimal valid i386 PE (MZ + COFF + opt-hdr + import table +
    embedded strings).

    IMAGE_OPTIONAL_HEADER32 is exactly 224 (0xE0) bytes:
      Standard fields   28  (Magic 2, LinkerVer 1+1, SizeOfCode 4,
                             SizeOfInitData 4, SizeOfUninitData 4,
                             EntryPoint 4, BaseOfCode 4, BaseOfData 4,
                             ImageBase 4)
      Windows-specific  68  (SectionAlign 4, FileAlign 4,
                             MajorOS 2, MinorOS 2, MajorImg 2, MinorImg 2,
                             MajorSub 2, MinorSub 2, Win32Ver 4,
                             SizeOfImage 4, SizeOfHeaders 4, CheckSum 4,
                             Subsystem 2, DllChars 2,
                             StackReserve 4, StackCommit 4,
                             HeapReserve 4, HeapCommit 4,
                             LoaderFlags 4, NumDirs 4)
      DataDirectory    128  (16 x 8)
      Total: 28 + 68 + 128 = 224  ✓
    """
    FILE_ALIGN = 0x200
    SEC_ALIGN  = 0x1000
    IMAGE_BASE = 0x00400000
    sec_rva    = SEC_ALIGN        # RVA of our single section

    def upa(v, a):
        return (v + a - 1) & ~(a - 1)

    # ---------- DLLs / functions to import ----------
    imports_spec = [
        ("kernel32.dll", [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "Sleep", "QueryPerformanceCounter", "GetTickCount",
            "VirtualAlloc", "VirtualFree",
            "GlobalMemoryStatusEx",
            "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
            "GetCurrentProcess", "ExitProcess",
        ]),
        ("user32.dll", ["FindWindowA"]),
    ]

    # ---------- Build section payload ----------
    payload = bytearray()

    # Tiny x86 stub: xor eax,eax; ret
    payload += bytes([0x31, 0xC0, 0xC3])
    while len(payload) % 4:
        payload += b'\x00'

    # Embedded string constants (trigger static-analysis hits)
    for s in [
        b"VBoxGuestAdditions\x00",
        b"vmtoolsd.exe\x00",
        b"QEMU HARDDISK\x00",
        b"C:\\agent\\agent.py\x00",
        b"00:05:69:AA:BB:CC\x00",
        b"08:00:27:00:00:00\x00",
        b"vmmouse.sys\x00",
        b"VBoxMouse.sys\x00",
        b"ollydbg\x00",
        b"x64dbg\x00",
        b"ida.exe\x00",
        b"Wireshark\x00",
        b"Process Hacker\x00",
        b"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\x00",
        b"sandbox\x00",
        b"sample.exe\x00",
    ]:
        payload += s
    while len(payload) % 4:
        payload += b'\x00'

    # ---------- Import table ----------
    per_dll = [{"name": n, "funcs": fns} for n, fns in imports_spec]
    num_dlls = len(per_dll)

    # IMAGE_IMPORT_DESCRIPTOR array (null-terminated)
    import_dir_off = len(payload)
    payload += b'\x00' * ((num_dlls + 1) * 20)

    # INT arrays
    for di in per_dll:
        di["int_off"] = len(payload)
        payload += b'\x00' * ((len(di["funcs"]) + 1) * 4)

    # IAT arrays
    for di in per_dll:
        di["iat_off"] = len(payload)
        payload += b'\x00' * ((len(di["funcs"]) + 1) * 4)

    # Hint/Name entries, patch INT & IAT
    for di in per_dll:
        for i, fn in enumerate(di["funcs"]):
            rva = sec_rva + len(payload)
            for off_field in ("int_off", "iat_off"):
                o = di[off_field] + i * 4
                payload[o:o+4] = struct.pack("<I", rva)
            payload += struct.pack("<H", 0)
            payload += fn.encode("ascii") + b'\x00'
            if len(fn) % 2 == 0:
                payload += b'\x00'

    # DLL name strings
    for di in per_dll:
        di["name_off"] = len(payload)
        payload += di["name"].encode("ascii") + b'\x00'
        if len(di["name"]) % 2 == 0:
            payload += b'\x00'

    # Patch IMAGE_IMPORT_DESCRIPTOR
    for i, di in enumerate(per_dll):
        o = import_dir_off + i * 20
        payload[o:o+20] = struct.pack(
            "<IIIII",
            sec_rva + di["int_off"],
            0,
            0xFFFFFFFF,
            sec_rva + di["name_off"],
            sec_rva + di["iat_off"],
        )

    raw_sec_size  = upa(len(payload), FILE_ALIGN)
    virt_sec_size = upa(len(payload), SEC_ALIGN)

    # ---------- PE layout ----------
    pe_off        = 0x40      # e_lfanew
    opt_hdr_size  = 0xE0      # 224 bytes exactly
    n_sects       = 1
    hdrs_size     = upa(pe_off + 4 + 20 + opt_hdr_size + n_sects * 40, FILE_ALIGN)
    size_of_image = upa(sec_rva + virt_sec_size, SEC_ALIGN)

    # Data directories (128 bytes)
    dd = bytearray(128)
    import_dir_rva = sec_rva + import_dir_off
    struct.pack_into("<II", dd,  1 * 8, import_dir_rva, (num_dlls + 1) * 20)
    iat_rva_first  = sec_rva + per_dll[0]["iat_off"]
    iat_total = (
        per_dll[-1]["iat_off"] + (len(per_dll[-1]["funcs"]) + 1) * 4
        - per_dll[0]["iat_off"]
    )
    struct.pack_into("<II", dd, 12 * 8, iat_rva_first, iat_total)

    # IMAGE_OPTIONAL_HEADER32 — field by field to guarantee 224 bytes
    # Standard fields: 2+1+1+4+4+4+4+4+4+4 = 32 ... wait:
    #   Magic(2) MajLnk(1) MinLnk(1) SzCode(4) SzInitData(4)
    #   SzUninitData(4) EP(4) BaseOfCode(4) BaseOfData(4) ImageBase(4) = 32
    # Windows-specific: SectionAlign(4) FileAlign(4) MajOS(2) MinOS(2)
    #   MajImg(2) MinImg(2) MajSub(2) MinSub(2) Win32Ver(4) SzImg(4)
    #   SzHdrs(4) CkSum(4) Sub(2) DllChr(2) StackRsv(4) StackCmt(4)
    #   HeapRsv(4) HeapCmt(4) LoaderFlags(4) NumDirs(4) = 64
    # DataDir: 128
    # Total: 32 + 64 + 128 = 224 ✓

    opt  = struct.pack("<HBBIIIIIII",         # 2+1+1+4*7 = 32? Let's verify:
        0x010B,                                # Magic (2)
        14, 0,                                 # MajLinker, MinLinker (1+1)
        upa(3, FILE_ALIGN),                    # SizeOfCode (4)
        0,                                     # SizeOfInitializedData (4)
        0,                                     # SizeOfUninitializedData (4)
        sec_rva,                               # AddressOfEntryPoint (4)
        sec_rva,                               # BaseOfCode (4)
        sec_rva,                               # BaseOfData (4)
        IMAGE_BASE,                            # ImageBase (4)
    )                                          # = 2+1+1+4+4+4+4+4+4+4 = 32 ✓
    opt += struct.pack("<IIHHHHHHIIIIHH",      # 4+4+2+2+2+2+2+2+4+4+4+4+2+2 = 40
        SEC_ALIGN,                             # SectionAlignment (4)
        FILE_ALIGN,                            # FileAlignment (4)
        6, 0,                                  # MajOS, MinOS (2+2)
        0, 0,                                  # MajImage, MinImage (2+2)
        6, 0,                                  # MajSubsystem, MinSubsystem (2+2)
        0,                                     # Win32VersionValue (4)
        size_of_image,                         # SizeOfImage (4)
        hdrs_size,                             # SizeOfHeaders (4)
        0,                                     # CheckSum (4)
        3,                                     # Subsystem (2) — CUI
        0x0140,                                # DllCharacteristics (2)
    )                                          # = 4+4+2+2+2+2+2+2+4+4+4+4+2+2 = 40
    opt += struct.pack("<IIIIII",              # 6×4 = 24
        0x100000,                              # SizeOfStackReserve
        0x1000,                                # SizeOfStackCommit
        0x100000,                              # SizeOfHeapReserve
        0x1000,                                # SizeOfHeapCommit
        0,                                     # LoaderFlags
        16,                                    # NumberOfRvaAndSizes
    )
    opt += bytes(dd)                           # 128
    # Total: 32 + 40 + 24 + 128 = 224 ✓
    assert len(opt) == opt_hdr_size, f"opt size {len(opt)} != {opt_hdr_size}"

    # COFF header (20 bytes)
    coff = struct.pack(
        "<HHIIIHH",
        0x014C, n_sects, 0x60000000,
        0, 0,
        opt_hdr_size,
        0x0102,   # EXE | 32-bit
    )

    # Section header (40 bytes)
    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b'.mix\x00\x00\x00\x00',
        len(payload), sec_rva, raw_sec_size, hdrs_size,
        0, 0, 0, 0,
        0xE0000020,   # CODE + INITIALIZED_DATA + MEM_EXECUTE + MEM_READ + MEM_WRITE
    )

    # MZ stub (64 bytes)
    mz = bytearray(64)
    mz[0:2] = b'MZ'
    struct.pack_into("<I", mz, 60, pe_off)

    # Assemble
    out = bytearray(bytes(mz))
    assert len(out) == pe_off
    out += b'PE\x00\x00' + coff + opt + sec_hdr
    while len(out) < hdrs_size:
        out += b'\x00'
    out += bytes(payload)
    while len(out) < hdrs_size + raw_sec_size:
        out += b'\x00'

    return bytes(out)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    os.makedirs(HERE, exist_ok=True)

    with open(SAMPLE_C_PATH, "w", encoding="utf-8") as f:
        f.write(SAMPLE_C_SOURCE)
    print(f"[+] Written C source: {SAMPLE_C_PATH}")

    compiled = try_compile_gcc()

    if not compiled:
        print("[~] GCC unavailable — building PE stub...")
        pe_bytes = build_stub_pe()
        with open(SAMPLE_EXE_PATH, "wb") as f:
            f.write(pe_bytes)
        print(f"[+] Written PE stub: {SAMPLE_EXE_PATH}")

    if os.path.isfile(SAMPLE_EXE_PATH):
        with open(SAMPLE_EXE_PATH, "rb") as f:
            data = f.read()
        sha256 = hashlib.sha256(data).hexdigest()
        print(f"[+] sample.exe ready  : {SAMPLE_EXE_PATH}")
        print(f"    Size              : {len(data):,} bytes")
        print(f"    SHA-256           : {sha256}")
    else:
        print("[-] Failed to produce sample.exe")
        sys.exit(1)


if __name__ == "__main__":
    main()
