# Person 2 Handover: Test Samples & Dynamic Behavioral Dossier

This document provides **Person 2 (Dynamic Analysis & Behavioral Detection)** with the full catalog of test samples, their runtime behavioral profiles, expected API execution traces, and the data schema contract required by **Person 3**.

---

## 1. Sample Inventory

All executable samples are located in the [`dataset/`](../dataset/) directory:

### Group A: Suspicious / Anti-Analysis Samples (`dataset/suspicious/`)

| Filename | SHA256 Hash | Size | Primary Evasion Focus |
|---|---|---|---|
| [`sample_anti_debug.exe`](../dataset/suspicious/sample_anti_debug.exe) | `2b07b614f98d80e3088827af10ecdfd41900f471aba14da32e0cbabb1ad4f174` | 42,613 B | Debugger detection via API checks & window titles |
| [`sample_anti_vm.exe`](../dataset/suspicious/sample_anti_vm.exe) | `b58e2432f4f3d79f93f7e0f36edb70e31ea4c5d5dd1c498de1fd983b93ca2acc` | 41,488 B | Hypervisor, driver, MAC address, and disk checks |
| [`sample_timing_evasion.exe`](../dataset/suspicious/sample_timing_evasion.exe) | `66091c02ec628a967928ad56b0c5228e799fd2191f374ec6313b2a3e6407a32e` | 42,363 B | Sleep-skipping & time-differential detection |
| [`sample_env_checks.exe`](../dataset/suspicious/sample_env_checks.exe) | `050914a407397b7a48c578daa39e1de3d38a3028f2b5fed1184b4079729ee064` | 42,686 B | CPU core count, RAM size, and process list scanning |
| [`sample_multi_evasion.exe`](../dataset/suspicious/sample_multi_evasion.exe) | `eb6c21d21ddd41104ef07c90f95faeabcf89e64dff71f6f09ac20dd75d740f07` | 42,990 B | Full multi-vector evasion (Debugger, VM, Timing, Env) |
| [`sample_packed_crypt.exe`](../dataset/suspicious/sample_packed_crypt.exe) | `55c42456a41b733d6b882f09941a6375558ffd3d45943cbe7fffa8f24eb40b87` | 49,718 B | Overlay high-entropy packing with VM checks |

### Group B: Benign Baseline Samples (`dataset/benign/`)

| Filename | SHA256 Hash | Size | Purpose |
|---|---|---|---|
| [`attrib.exe`](../dataset/benign/attrib.exe) | `064181108cd8d7f110cc11b84dbf2d7f18fd5f52a2ee989985d88a969f093dbe` | 45,056 B | Legitimate Windows file attribute utility |
| [`ping.exe`](../dataset/benign/ping.exe) | `e4224d18c3c96826e6f4240893fac02c8a1ff335ce92614fc8744369594dd468` | 45,056 B | Legitimate Windows network utility |
| [`whoami.exe`](../dataset/benign/whoami.exe) | `23240ef9f8b0a9a324110b1c2331de31dc1b0e08f5359cb707e51a939af56cd3` | 98,304 B | Legitimate Windows user info utility |
| [`benign_hello.exe`](../dataset/benign/benign_hello.exe) | `31ab3447e351b8b16a0354d0ab362827345fbbfb4f683a94a80ae30d3d8eb085` | 40,764 B | Clean utility program (prints greeting and exits 0) |

---

## 2. Runtime Behavioral Profiles (What Happens During Execution)

### 1. `sample_anti_debug.exe`
- **What Person 2 Should Monitor:**
  - Invocation of `IsDebuggerPresent()`.
  - Invocation of `CheckRemoteDebuggerPresent(GetCurrentProcess(), ...)`.
  - Calls to `OutputDebugStringA(...)`.
  - Calls to `FindWindowA(...)` querying for window names: `"x64dbg"`, `"ollydbg"`, `"ida.exe"`, `"Wireshark"`, `"Process Hacker"`.
- **Runtime Outcome:**
  - If a debugger or matching window is detected $\rightarrow$ Exits with returncode `1` and prints `"Debugger detected via..."` to stdout.
  - If no debugger is present $\rightarrow$ Exits with returncode `0`.

### 2. `sample_anti_vm.exe`
- **What Person 2 Should Monitor:**
  - Invocation of `GetDiskFreeSpaceExA("C:\\", ...)`.
  - String evaluation of VM artifacts: `VBoxGuestAdditions`, `VBoxMouse.sys`, `vmtoolsd.exe`, `00:05:69:AA:BB:CC`, `08:00:27:11:22:33`.
- **Runtime Outcome:**
  - Prints scan parameters to stdout and terminates cleanly.

### 3. `sample_timing_evasion.exe`
- **What Person 2 Should Monitor:**
  - Calls to `GetTickCount()` and `QueryPerformanceCounter()`.
  - Call to `Sleep(2000)`.
  - Re-query of `GetTickCount()` and `QueryPerformanceCounter()`.
  - Comparison logic: measures if `tickEnd - tickStart < 1800 ms`.
- **Runtime Outcome:**
  - If the sandbox **fast-forwards sleep** (elapsed $< 1800$ ms) $\rightarrow$ Prints `"Sandbox timing acceleration detected! Fast-forwarding sleep."` and exits with code `1`.
  - If allowed to sleep genuine 2000 ms $\rightarrow$ Prints `"Elapsed: ~2000 ms"` and exits with code `0`.

### 4. `sample_env_checks.exe`
- **What Person 2 Should Monitor:**
  - Call to `GetSystemInfo(...)` (reads `dwNumberOfProcessors`).
  - Call to `GlobalMemoryStatusEx(...)` (reads RAM size).
  - Call to `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)`.
  - Process enumeration loop: `Process32First` and `Process32Next` scanning active process names for `"sample"` or `"sandbox"`.
- **Runtime Outcome:**
  - If CPU cores $< 2$ $\rightarrow$ prints `"Suspiciously low CPU count (< 2 cores)"`.
  - If snapshot finds sandbox process names $\rightarrow$ prints `"Suspicious sandbox process name: <name>"`.

### 5. `sample_multi_evasion.exe`
- **What Person 2 Should Monitor:**
  - Combines all 4 behaviors in a single execution chain:
    1. Debugger checks (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`).
    2. Hardware/Environment checks (`GetSystemInfo`, `GlobalMemoryStatusEx`, `CreateToolhelp32Snapshot`).
    3. Timing checks (`GetTickCount`, `Sleep(1000)`).
- **Runtime Outcome:**
  - Ideal comprehensive test target for Person 2's end-to-end dynamic monitor.

### 6. Benign Samples (`attrib.exe`, `ping.exe`, `whoami.exe`, `benign_hello.exe`)
- **What Person 2 Should Monitor:**
  - No evasion API calls, no sleep-acceleration checks, no process enumeration snapshots.
  - Normal clean exit codes (0).

---

## 3. Recommended Dynamic Analysis Framework for Person 2

Person 2 can build their dynamic analysis module using Python:

1. **Option A: Python Process Monitor & Subprocess Tracing (Lightweight)**
   - Use `subprocess.Popen` with timeout monitoring.
   - Measure actual execution time vs. expected execution time to detect sleep evasion.
   - Inspect exit code (`0` vs `1`) and capture `stdout`/`stderr` indicators.
   - Query runtime memory and process metrics using `psutil`.

2. **Option B: API Hooking via Frida or PyWin32 (Deep Tracing)**
   - Hook target APIs: `IsDebuggerPresent`, `Sleep`, `CreateToolhelp32Snapshot`, `GetSystemInfo`.
   - Record call counts, timestamps, and parameters.

---

## 4. Required Output Contract for Person 3

To ensure Person 2's dynamic output integrates seamlessly with Person 1's static output, Person 2 should generate an `output/dynamic_features.json` formatted like this:

```json
[
  {
    "filename": "sample_multi_evasion.exe",
    "execution_time_ms": 1015,
    "exit_code": 0,
    "dynamic_indicators": {
      "vm_detected": false,
      "debugger_detected": true,
      "environment_checked": true,
      "timing_evasion_detected": true
    },
    "runtime_apis_observed": [
      "IsDebuggerPresent",
      "CheckRemoteDebuggerPresent",
      "GetSystemInfo",
      "GlobalMemoryStatusEx",
      "CreateToolhelp32Snapshot",
      "Sleep",
      "GetTickCount"
    ],
    "process_activity": {
      "spawned_subprocesses": 0,
      "memory_peak_kb": 1240
    },
    "dynamic_risk_score": 75.0,
    "dynamic_risk_level": "HIGH"
  }
]
```
