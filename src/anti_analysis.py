"""Anti-Analysis Detection Engine
Defines indicators and heuristic rules for:
1. VM / Hypervisor Detection
2. Debugger Detection
3. Environment Checks
4. Timing-Related Checks
"""

import re
from typing import Dict, List, Set, Any


# 1. VM / Hypervisor Detection Signatures
VM_APIS = {
    "getsystemmetrics",
    "setupdigetclassdevsa",
    "setupdigetclassdevsw",
    "deviceiocontrol",
    "getdiskfreespaceexa",
    "getdiskfreespacew",
    "getdiskfreespaceexw",
    "wine_get_version",
    "wine_get_unix_file_name",
}

VM_STRING_PATTERNS = [
    re.compile(r"(?:vboxguest|vboxmouse|vboxsf|vboxvideo|vboxservice|vboxtray|vboxmini)", re.IGNORECASE),
    re.compile(r"(?:virtualbox|oracle\s+vm)", re.IGNORECASE),
    re.compile(r"(?:vmware|vmtoolsd|vmmouse|vmhgfs|vmusbmouse|vm3dgl|vmci\.sys)", re.IGNORECASE),
    re.compile(r"(?:qemu|bochs|red\s+hat\s+virtio|kvm)", re.IGNORECASE),
    re.compile(r"(?:xen|vmbus\.sys|hyper-v)", re.IGNORECASE),
    re.compile(r"(?:c:\\cuckoo|c:\\agent\\agent\.py|sandbox|sample\.exe)", re.IGNORECASE),
    re.compile(r"scsi\s+port\s+0.*scsi\s+bus\s+0.*target\s+id\s+0", re.IGNORECASE),
    re.compile(r"00:05:69|00:0c:29|00:50:56|08:00:27", re.IGNORECASE),
]

# 2. Debugger Detection Signatures
DEBUGGER_APIS = {
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "outputdebugstringa",
    "outputdebugstringw",
    "ntqueryinformationprocess",
    "zwqueryinformationprocess",
    "ntsetinformationthread",
    "zwsetinformationthread",
    "ntquerysysteminformation",
    "findwindowa",
    "findwindoww",
    "findwindowexa",
    "findwindowexw",
    "setunhandledexceptionfilter",
    "raiseexception",
    "debugactiveprocess",
    "debugbreak",
}

DEBUGGER_STRING_PATTERNS = [
    re.compile(r"\b(?:ollydbg|x64dbg|x32dbg|windbg|immunity|radare2|ghidra)\b", re.IGNORECASE),
    re.compile(r"\b(?:ida\.exe|idag\.exe|ida64\.exe|ida\s+pro)\b", re.IGNORECASE),
    re.compile(r"\b(?:wireshark|procmon|procexp|process\s*hacker|regshot|tcpview|fiddler)\b", re.IGNORECASE),
    re.compile(r"\b(?:scylla|dnspy|de4dot|megadumper|cheat\s*engine)\b", re.IGNORECASE),
]

# 3. Environment Check Signatures
ENVIRONMENT_APIS = {
    "getsysteminfo",
    "getnativesysteminfo",
    "getactiveprocessorcount",
    "getlogicalprocessorinformation",
    "globalmemorystatusex",
    "globalmemorystatus",
    "getphysicallyinstalledsystemmemory",
    "createtoolhelp32snapshot",
    "process32first",
    "process32firstw",
    "process32next",
    "process32nextw",
    "enumprocesses",
    "enumprocessmodules",
    "openscmanagera",
    "openscmanagerw",
    "enumservicesstatusa",
    "enumservicesstatusw",
    "enumservicesstatusexa",
    "enumservicesstatusexw",
    "getadaptersinfo",
    "getadaptersaddresses",
    "getnetworkparams",
    "enumwindows",
    "enumdesktopwindows",
    "getcursorpos",
    "getlastinputinfo",
    "countclipboardformats",
}

ENVIRONMENT_STRING_PATTERNS = [
    re.compile(r"\b(?:currentuser|sandbox|malware|virus|sample|test-pc)\b", re.IGNORECASE),
    re.compile(r"software\\microsoft\\windows\\currentversion\\uninstall", re.IGNORECASE),
    re.compile(r"system\\currentcontrolset\\services\\disk\\enum", re.IGNORECASE),
]

# 4. Timing Check Signatures
TIMING_APIS = {
    "queryperformancecounter",
    "queryperformancefrequency",
    "gettickcount",
    "gettickcount64",
    "timegettime",
    "sleep",
    "sleepex",
    "ntdelayexecution",
    "zwdelayexecution",
    "waitforsingleobject",
    "waitformultipleobjects",
    "settimer",
}

TIMING_STRING_PATTERNS = [
    re.compile(r"\brdtsc\b", re.IGNORECASE),
    re.compile(r"\bgettickcount\b", re.IGNORECASE),
    re.compile(r"\bqueryperformancecounter\b", re.IGNORECASE),
]


class AntiAnalysisDetector:
    """Evaluates extracted PE information and strings against anti-analysis rules."""

    def __init__(self, imports: Dict[str, List[str]], strings: List[str]):
        self.imports = imports
        self.strings = strings

        # Flatten imported functions in lowercase for quick lookup
        self.imported_funcs_lower: Set[str] = set()
        for funcs in imports.values():
            for f in funcs:
                self.imported_funcs_lower.add(f.lower())

    def detect_vm(self) -> Dict[str, Any]:
        """Detect Virtual Machine / Sandbox static indicators."""
        matched_apis = [api for api in VM_APIS if api in self.imported_funcs_lower]

        matched_strings: List[str] = []
        for s in self.strings:
            for pat in VM_STRING_PATTERNS:
                if pat.search(s):
                    matched_strings.append(s.strip())
                    break
        matched_strings = list(dict.fromkeys(matched_strings))[:20]  # Deduplicate & limit

        detected = bool(matched_apis or matched_strings)
        evidence = []
        if matched_apis:
            evidence.append(f"Imports associated with VM/device queries: {', '.join(matched_apis)}")
        if matched_strings:
            evidence.append(f"Strings matching VM/Hypervisor signatures: {', '.join(matched_strings[:5])}")

        return {
            "detected": detected,
            "matched_apis": matched_apis,
            "matched_strings": matched_strings,
            "api_count": len(matched_apis),
            "string_count": len(matched_strings),
            "total_indicators": len(matched_apis) + len(matched_strings),
            "evidence": evidence,
        }

    def detect_debugger(self) -> Dict[str, Any]:
        """Detect anti-debugging static indicators."""
        matched_apis = [api for api in DEBUGGER_APIS if api in self.imported_funcs_lower]

        matched_strings: List[str] = []
        for s in self.strings:
            for pat in DEBUGGER_STRING_PATTERNS:
                if pat.search(s):
                    matched_strings.append(s.strip())
                    break
        matched_strings = list(dict.fromkeys(matched_strings))[:20]

        detected = bool(matched_apis or matched_strings)
        evidence = []
        if matched_apis:
            evidence.append(f"Anti-debugging APIs imported: {', '.join(matched_apis)}")
        if matched_strings:
            evidence.append(f"Debugger or analysis tool names found: {', '.join(matched_strings[:5])}")

        return {
            "detected": detected,
            "matched_apis": matched_apis,
            "matched_strings": matched_strings,
            "api_count": len(matched_apis),
            "string_count": len(matched_strings),
            "total_indicators": len(matched_apis) + len(matched_strings),
            "evidence": evidence,
        }

    def detect_environment(self) -> Dict[str, Any]:
        """Detect environment checking static indicators."""
        matched_apis = [api for api in ENVIRONMENT_APIS if api in self.imported_funcs_lower]

        matched_strings: List[str] = []
        for s in self.strings:
            for pat in ENVIRONMENT_STRING_PATTERNS:
                if pat.search(s):
                    matched_strings.append(s.strip())
                    break
        matched_strings = list(dict.fromkeys(matched_strings))[:20]

        detected = bool(matched_apis or matched_strings)
        evidence = []
        if matched_apis:
            evidence.append(f"Hardware/environment enumeration APIs: {', '.join(matched_apis)}")
        if matched_strings:
            evidence.append(f"Environment check patterns: {', '.join(matched_strings[:5])}")

        return {
            "detected": detected,
            "matched_apis": matched_apis,
            "matched_strings": matched_strings,
            "api_count": len(matched_apis),
            "string_count": len(matched_strings),
            "total_indicators": len(matched_apis) + len(matched_strings),
            "evidence": evidence,
        }

    def detect_timing(self) -> Dict[str, Any]:
        """Detect timing-based checks / evasion indicators."""
        matched_apis = [api for api in TIMING_APIS if api in self.imported_funcs_lower]

        matched_strings: List[str] = []
        for s in self.strings:
            for pat in TIMING_STRING_PATTERNS:
                if pat.search(s):
                    matched_strings.append(s.strip())
                    break
        matched_strings = list(dict.fromkeys(matched_strings))[:20]

        has_timer = any(a in matched_apis for a in ["gettickcount", "gettickcount64", "queryperformancecounter", "timegettime"])
        has_sleep = any(a in matched_apis for a in ["sleep", "sleepex", "ntdelayexecution", "zwdelayexecution"])
        has_timing_pair = has_timer and has_sleep

        detected = bool(matched_apis or matched_strings)
        evidence = []
        if matched_apis:
            evidence.append(f"Timing APIs imported: {', '.join(matched_apis)}")
        if has_timing_pair:
            evidence.append("Heuristic hit: High-resolution timer paired with sleep delay (evasion pattern)")
        if matched_strings:
            evidence.append(f"Timing check strings: {', '.join(matched_strings[:5])}")

        return {
            "detected": detected,
            "has_timing_pair": has_timing_pair,
            "matched_apis": matched_apis,
            "matched_strings": matched_strings,
            "api_count": len(matched_apis),
            "string_count": len(matched_strings),
            "total_indicators": len(matched_apis) + len(matched_strings),
            "evidence": evidence,
        }

    def analyze_all(self) -> Dict[str, Any]:
        """Run all static anti-analysis detection modules."""
        vm_res = self.detect_vm()
        dbg_res = self.detect_debugger()
        env_res = self.detect_environment()
        timing_res = self.detect_timing()

        total_anti_analysis_indicators = (
            vm_res["total_indicators"]
            + dbg_res["total_indicators"]
            + env_res["total_indicators"]
            + timing_res["total_indicators"]
        )

        categories_triggered = sum([
            1 if vm_res["detected"] else 0,
            1 if dbg_res["detected"] else 0,
            1 if env_res["detected"] else 0,
            1 if timing_res["detected"] else 0,
        ])

        return {
            "vm_detection": vm_res,
            "debugger_detection": dbg_res,
            "environment_checks": env_res,
            "timing_checks": timing_res,
            "summary": {
                "total_indicators": total_anti_analysis_indicators,
                "categories_triggered_count": categories_triggered,
                "any_anti_analysis_detected": categories_triggered > 0,
            }
        }
