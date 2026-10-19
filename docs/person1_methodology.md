# Person 1 — Static Analysis & Feature Extraction Methodology & Results

## 1. Executive Summary

This document describes the design, implementation, and evaluation of the **Static Analysis and Feature Extraction System** developed by **Person 1** for the Anti-Analysis Malware Detection pipeline.

The static analysis system evaluates Windows Portable Executable (`.exe`, `.dll`, `.sys`) binaries in an offline state—**without execution**. It parses binary headers, extracts structural sections, calculates Shannon entropy, scans for ASCII/Unicode strings, and runs a rules-based anti-analysis detection engine to detect evasion behaviors:
- **VM / Hypervisor Detection**
- **Debugger Detection**
- **Environment & Hardware Fingerprinting**
- **Timing & Delay Evasion**

The output is formatted for **Person 3 (Detection Engine & Integration)** in two formats:
1. An **Explainable JSON Dataset** (`output/static_features.json`) detailing matched APIs, strings, and evidence.
2. A **Tabular Feature Vector CSV** (`output/static_features.csv`) with normalized numerical and categorical features for risk scoring and ML models.

---

## 2. System Architecture

```
                    ┌───────────────────────────────┐
                    │      Input Executable         │
                    └───────────────┬───────────────┘
                                    │
       ┌────────────────────────────┴───────────────────────────┐
       ▼                                                        ▼
┌───────────────────────────────┐              ┌────────────────────────────────┐
│   PE Parser (pe_parser.py)    │              │ String Extractor (string_extr) │
│ - Hashes (MD5, SHA1, SHA256)  │              │ - ASCII & UTF-16LE decoding    │
│ - Headers & Architecture      │              │ - Regex (IPs, URLs, Registry)  │
│ - Section Tables & Entropies  │              │ - Driver & Tool References     │
│ - Import & Export Tables      │              └────────────────┬───────────────┘
└──────────────┬────────────────┘                               │
               │                                                │
               └───────────────────────┬────────────────────────┘
                                       ▼
                     ┌────────────────────────────────────┐
                     │ Anti-Analysis Engine (anti_analy)  │
                     │ - VM / Hypervisor Rules            │
                     │ - Anti-Debugging Rules             │
                     │ - Environment Check Rules          │
                     │ - Timing & Delay Heuristics        │
                     └─────────────────┬──────────────────┘
                                       ▼
                     ┌────────────────────────────────────┐
                     │ Feature Extractor (feature_extr)   │
                     │ - Packaging & Risk Heuristics      │
                     │ - Serialization to JSON & CSV      │
                     └─────────────────┬──────────────────┘
                                       │
                  ┌────────────────────┴───────────────────┐
                  ▼                                        ▼
    ┌───────────────────────────┐            ┌───────────────────────────┐
    │ output/static_features.json│           │ output/static_features.csv│
    │ (For Person 3 Explanations│            │ (For Person 3 Risk Scoring│
    │  & Dashboard Visualization)│           │  & Machine Learning)      │
    └───────────────────────────┘            └───────────────────────────┘
```

---

## 3. Detailed Component Breakdown

### 3.1 PE Parsing & Section Entropy (`src/pe_parser.py`)
- **Header Parsing**: Extracts machine architecture (x86/x64), timestamp, entry point address, image base, subsystem, and DLL characteristics.
- **Shannon Entropy Calculation**: 
  $$H = -\sum_{i=0}^{255} p_i \log_2(p_i)$$
  Calculated per section and for file overlay. Sections with $H \ge 7.0$ (maximum 8.0) indicate compression, encryption, or packing.
- **Import / Export Resolution**: Categorizes all imported libraries and functions (including ordinals) for signature matching.
- **Overlay Detection**: Detects appended overlay payloads and measures overlay size and entropy.

### 3.2 String & Artifact Extraction (`src/string_extractor.py`)
- Scans raw binary buffers for both ASCII (`[\x20-\x7e]{4,}`) and UTF-16LE (`(?:[\x20-\x7e]\x00){4,}`) strings.
- Regex pattern extractors for:
  - IPv4 addresses: `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`
  - URLs: `https?://[a-zA-Z0-9_\-\./:]+`
  - Registry keys: `(?:HKLM|HKCU|SOFTWARE\\|SYSTEM\\CurrentControlSet|HARDWARE\\DEVICEMAP)...`
  - Kernel Drivers: `[a-zA-Z0-9_\-\.]+\.(?:sys|vxd|drv)`

### 3.3 Anti-Analysis Rule Catalog (`src/anti_analysis.py`)

#### 1. VM & Hypervisor Detection
- **APIs**: `GetSystemMetrics`, `SetupDiGetClassDevsA/W`, `DeviceIoControl`, `GetDiskFreeSpaceExA/W`, `wine_get_version`.
- **String Signatures**: VirtualBox artifacts (`VBoxGuestAdditions`, `VBoxMouse.sys`, `VBoxVideo.sys`, `VBoxService`), VMware artifacts (`vmtoolsd.exe`, `vmmouse.sys`, `vmhgfs.sys`, `VMware Virtual IDE Hard Drive`), QEMU/KVM (`Red Hat VirtIO`, `QEMU HARDDISK`), MAC address vendor prefixes (`00:05:69`, `00:0c:29`, `00:50:56`, `08:00:27`), and SCSI registry keys (`HARDWARE\DEVICEMAP\Scsi`).

#### 2. Debugger Detection
- **APIs**: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `OutputDebugStringA/W`, `NtQueryInformationProcess`, `ZwQueryInformationProcess`, `NtSetInformationThread` (ThreadHideFromDebugger), `FindWindowA/W`, `FindWindowExA/W`, `SetUnhandledExceptionFilter`, `RaiseException`, `DebugActiveProcess`.
- **String Signatures**: Known debugger/reversing tools: `ollydbg`, `x64dbg`, `x32dbg`, `windbg`, `ida.exe`, `idag.exe`, `ida pro`, `ghidra`, `wireshark`, `procmon`, `procexp`, `process hacker`, `cheat engine`.

#### 3. Environment & Hardware Fingerprinting
- **APIs**: `GetSystemInfo`, `GetNativeSystemInfo`, `GetActiveProcessorCount` (CPU core count checks), `GlobalMemoryStatusEx` (RAM checks), `CreateToolhelp32Snapshot`, `Process32First/Next`, `EnumProcesses` (process enumeration), `GetAdaptersInfo`, `EnumWindows`.
- **String Signatures**: Sandbox / analysis usernames: `sandbox`, `malware`, `currentuser`, `sample`, `test-pc`.

#### 4. Timing & Delay Checks
- **APIs**: `QueryPerformanceCounter`, `QueryPerformanceFrequency`, `GetTickCount`, `GetTickCount64`, `timeGetTime`, `Sleep`, `SleepEx`, `NtDelayExecution`.
- **Heuristics**: High-resolution timer paired with sleep delay (`has_timing_pair`), which indicates sleep-acceleration bypass checks used to defeat automated sandboxes.

---

## 4. Feature Schema Handover for Person 3

### 4.1 Explainable JSON Schema (`output/static_features.json`)
Person 3 can read this file directly to populate the UI dashboard and explainable result cards:
```json
{
  "file_info": {
    "filename": "sample_multi_evasion.exe",
    "file_size": 42990,
    "sha256": "...",
    "is_valid_pe": true
  },
  "pe_summary": {
    "num_sections": 13,
    "max_section_entropy": 6.1087,
    "has_high_entropy_section": false,
    "total_dlls": 2,
    "total_imported_functions": 59,
    "packing_heuristic": { "is_packed": false }
  },
  "anti_analysis_indicators": {
    "vm_detection": { "detected": true, "evidence": ["..."] },
    "debugger_detection": { "detected": true, "evidence": ["..."] },
    "environment_checks": { "detected": true, "evidence": ["..."] },
    "timing_checks": { "detected": true, "evidence": ["..."] },
    "summary": {
      "total_indicators": 13,
      "categories_triggered_count": 4,
      "any_anti_analysis_detected": true
    }
  },
  "preliminary_assessment": {
    "static_risk_score": 80.0,
    "static_risk_level": "HIGH",
    "risk_factors": ["..."]
  }
}
```

### 4.2 Tabular CSV Dataset Schema (`output/static_features.csv`)
Used for numerical scoring, machine learning classification, and correlation with Person 2's dynamic features:

| Column Name | Type | Description |
|---|---|---|
| `filename` | string | Target executable name |
| `sha256` | string | SHA256 hash |
| `file_size` | integer | Size in bytes |
| `is_valid_pe` | integer (0/1) | Whether file parsed as PE |
| `num_sections` | integer | Number of PE sections |
| `max_entropy` | float | Peak section entropy |
| `avg_entropy` | float | Average section entropy |
| `has_high_entropy_section` | integer (0/1) | 1 if any section $\ge 7.0$ |
| `total_imported_dlls` | integer | Number of unique DLLs imported |
| `total_imported_functions` | integer | Total imported APIs count |
| `total_strings` | integer | Total ASCII/Unicode strings |
| `unique_strings` | integer | Unique strings count |
| `anti_vm_detected` | integer (0/1) | 1 if VM detection triggered |
| `anti_vm_api_count` | integer | Number of VM APIs imported |
| `anti_vm_string_count` | integer | Number of VM strings found |
| `anti_debug_detected` | integer (0/1) | 1 if Debugger detection triggered |
| `anti_debug_api_count` | integer | Number of Debugger APIs imported |
| `anti_debug_string_count` | integer | Number of Debugger strings found |
| `env_check_detected` | integer (0/1) | 1 if Environment checks triggered |
| `env_check_api_count` | integer | Number of Env APIs imported |
| `env_check_string_count`| integer | Number of Env strings found |
| `timing_check_detected` | integer (0/1) | 1 if Timing checks triggered |
| `timing_check_api_count`| integer | Number of Timing APIs imported |
| `timing_check_string_count`| integer | Number of Timing strings found |
| `has_timing_pair` | integer (0/1) | 1 if timer API + Sleep API present |
| `total_anti_analysis_indicators` | integer | Total hit count across all 4 types |
| `categories_triggered_count` | integer (0-4) | Number of evasion categories active |
| `is_packed` | integer (0/1) | 1 if packed/encrypted heuristic hit |
| `static_risk_score` | float | Preliminary static score (0-100) |
| `static_risk_level` | string | "LOW", "MEDIUM", or "HIGH" |

---

## 5. Dataset & Evaluation Results

A dataset of 10 samples (4 benign, 6 suspicious) was processed through the static analyzer:

| Sample Name | Type | VM Det | Debug Det | Env Det | Timing Det | Packed | Total Hits | Risk Level |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `attrib.exe` | Benign System | No | Yes* | No | No | No | 1 | **LOW** (40.0) |
| `benign_hello.exe` | Benign Utility| No | Yes* | No | No | No | 1 | **LOW** (25.0) |
| `ping.exe` | Benign System | No | Yes* | No | No | No | 1 | **LOW** (40.0) |
| `whoami.exe` | Benign System | No | Yes* | No | No | No | 1 | **LOW** (40.0) |
| `sample_anti_debug.exe` | Suspicious | No | **YES** | No | No | No | 10 | **LOW/MED** (25.0) |
| `sample_anti_vm.exe` | Suspicious | **YES** | Yes* | No | No | No | 11 | **MEDIUM** (50.0) |
| `sample_env_checks.exe` | Suspicious | **YES** | Yes* | **YES** | No | No | 11 | **HIGH** (65.0) |
| `sample_packed_crypt.exe`| Suspicious | **YES** | Yes* | No | No | **YES** | 11 | **HIGH** (70.0) |
| `sample_timing_evasion.exe`| Suspicious| **YES** | Yes* | **YES** | **YES** | No | 9 | **HIGH** (80.0) |
| `sample_multi_evasion.exe` | Suspicious| **YES** | **YES** | **YES** | **YES** | No | 13 | **HIGH** (80.0) |

*\*Note: Standard Windows runtime binaries and MinGW C runtimes routinely import `SetUnhandledExceptionFilter` for standard structured exception handling. Person 3's scoring logic can weight isolated runtime calls accordingly or pair them with Person 2's dynamic observation of active exception redirection.*

---

## 6. How Person 2 and Person 3 Use This Deliverable

1. **For Person 2 (Dynamic Analysis)**:
   - Person 2 can look at `anti_analysis_indicators` in `static_features.json` to configure the sandbox.
   - For example, if `has_timing_pair` is detected statically, Person 2 should monitor for `Sleep` manipulation and hook `GetTickCount` / `QueryPerformanceCounter` to observe if sleep-skipping was attempted during runtime.
   - If `sample_anti_vm.exe` is being analyzed, Person 2 should verify whether driver registry queries or MAC address checks occurred dynamically.

2. **For Person 3 (Detection Engine & Integration)**:
   - **Explainable Cards**: Use `static_features.json` directly to display evidence strings in the user interface.
   - **Score Fusion**: Combine `static_risk_score` from `static_features.csv` with Person 2's dynamic risk score.
   - **Correlation**: Check if static suspicious indicators (e.g. `is_debugger_present` import) match dynamic execution (e.g. `IsDebuggerPresent` was actually invoked and changed process flow).
