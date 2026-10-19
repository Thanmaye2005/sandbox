"""
export_single_sample.py
-----------------------
Runs the existing static analyzer on ONE PE file and writes the agreed
shared schema to output/static_features.json.

Usage:
    python export_single_sample.py --file samples/sample.exe
    python export_single_sample.py --file samples/sample.exe --output-dir output --sample-id S001

The terminal output (print_cli_summary) is preserved exactly as before.
The JSON exporter runs AFTER all analysis is complete and reflects only
real results — nothing is hard-coded.

Shared schema (schema_version 1.0):
{
    "schema_version": "1.0",
    "analysis_type": "static",
    "sample_id": "S001",
    "sample_name": "sample.exe",
    "sha256": "<actual hash>",
    "file_size": <int>,
    "valid_pe": <bool>,
    "sections": <int>,          # section count (ML-numeric)
    "imports": <int>,           # total imported function count (ML-numeric)
    "packed": <bool>,
    "static_indicators": {
        "vm_detection":       <bool>,
        "anti_debugging":     <bool>,
        "timing_check":       <bool>,
        "environment_check":  <bool>,
        "process_check":      <bool>,   # subset of environment_check
        "suspicious_imports": <bool>    # any suspicious API detected via imports
    },
    "evidence": {
        "vm_detection":       [<str>, ...],
        "anti_debugging":     [<str>, ...],
        "timing_check":       [<str>, ...],
        "environment_check":  [<str>, ...],
        "process_check":      [<str>, ...],
        "suspicious_imports": [<str>, ...]
    },
    "static_risk_score": <float>,
    "static_risk_level": "LOW|MEDIUM|HIGH"
}
"""

import os
import sys
import json
import argparse
from typing import Dict, Any, List

# Allow running from any directory
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from pe_parser import PEParser
from string_extractor import StringExtractor
from anti_analysis import AntiAnalysisDetector
from feature_extractor import FeatureExtractor
from analyzer import analyze_file, print_cli_summary


# ── Suspicious API sets for "suspicious_imports" indicator ─────────────────
# These APIs are commonly associated with malware behaviour regardless of
# which anti-analysis category they fall into.
SUSPICIOUS_IMPORT_APIS = {
    # Memory / shellcode injection
    "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
    "writeprocessmemory", "readprocessmemory", "createremotethread",
    "createremotethreadex", "ntcreatethreadex", "rtlcreateuserthread",
    # Process injection / hollowing
    "openprocess", "suspendthread", "resumethread",
    "ntunmapviewofsection", "zwunmapviewofsection",
    "setthreadcontext", "getthreadcontext",
    # Network (unexpected in many benign files)
    "wsastartup", "connect", "send", "recv", "internetopen", "internetopenurl",
    "httpsendrequesta", "httpsendrequeststringw",
    # Crypto / key material
    "cryptencrypt", "cryptdecrypt", "cryptgenkey", "cryptderivekey",
    # Lateral movement / persistence
    "regcreatekeyex", "regsetvalueex", "scheduledtasks", "schtasks",
    "copyfile", "movefile", "deletefile",
    # Anti-debugging (also flagged here as suspicious import evidence)
    "isdebuggerpresent", "checkremotedebuggerpresent",
    "ntqueryinformationprocess", "zwqueryinformationprocess",
}


def _collect_suspicious_import_evidence(pe_data: Dict[str, Any]) -> List[str]:
    """Return list of imported function names that match SUSPICIOUS_IMPORT_APIS."""
    found: List[str] = []
    imports: Dict[str, List[str]] = pe_data.get("imports", {})
    for _dll, funcs in imports.items():
        for func in funcs:
            if func.lower() in SUSPICIOUS_IMPORT_APIS:
                found.append(func)
    # Deduplicate while preserving original case
    seen = set()
    result = []
    for f in found:
        key = f.lower()
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


def _process_check_evidence(env_data: Dict[str, Any]) -> List[str]:
    """
    Extract evidence specifically related to process enumeration
    (a subset of environment_check indicators).
    Process-enumeration APIs: CreateToolhelp32Snapshot, Process32First/Next,
    EnumProcesses, EnumProcessModules.
    """
    process_apis = {
        "createtoolhelp32snapshot", "process32first", "process32firstw",
        "process32next", "process32nextw", "enumprocesses", "enumprocessmodules"
    }
    matched = [a for a in env_data.get("matched_apis", []) if a.lower() in process_apis]
    if matched:
        return [f"Process-enumeration APIs imported: {', '.join(matched)}"]
    return []


def build_shared_schema(
    report: Dict[str, Any],
    raw_pe: Dict[str, Any],
    sample_id: str = "S001",
) -> Dict[str, Any]:
    """
    Convert the full explainable report + raw PE data into the agreed shared
    schema. All values come from actual analysis results — nothing is hard-coded.
    """
    finfo = report["file_info"]
    pe_sum = report["pe_summary"]
    aa = report["anti_analysis_indicators"]
    risk = report["preliminary_assessment"]

    vm_data  = aa["vm_detection"]
    dbg_data = aa["debugger_detection"]
    env_data = aa["environment_checks"]
    tm_data  = aa["timing_checks"]

    # ── Suspicious imports ──────────────────────────────────────────────────
    susp_imports = _collect_suspicious_import_evidence(raw_pe)
    has_suspicious_imports = bool(susp_imports)

    # ── Process-check sub-indicator ─────────────────────────────────────────
    proc_ev = _process_check_evidence(env_data)
    has_process_check = bool(proc_ev)

    # ── Assemble indicator booleans ─────────────────────────────────────────
    static_indicators = {
        "vm_detection":       vm_data.get("detected", False),
        "anti_debugging":     dbg_data.get("detected", False),
        "timing_check":       tm_data.get("detected", False),
        "environment_check":  env_data.get("detected", False),
        "process_check":      has_process_check,
        "suspicious_imports": has_suspicious_imports,
    }

    # ── Evidence lists: use actual strings from the analyzer ────────────────
    # vm_detection evidence
    vm_ev: List[str] = list(vm_data.get("matched_apis", []))
    vm_ev += list(vm_data.get("matched_strings", []))

    # anti_debugging evidence
    dbg_ev: List[str] = list(dbg_data.get("matched_apis", []))
    dbg_ev += list(dbg_data.get("matched_strings", []))

    # timing_check evidence
    tm_ev: List[str] = list(tm_data.get("matched_apis", []))
    tm_ev += list(tm_data.get("matched_strings", []))
    if tm_data.get("has_timing_pair"):
        tm_ev.append("timing_pair_heuristic")

    # environment_check evidence (non-process)
    env_ev: List[str] = [
        a for a in env_data.get("matched_apis", [])
        if a.lower() not in {
            "createtoolhelp32snapshot", "process32first", "process32firstw",
            "process32next", "process32nextw", "enumprocesses", "enumprocessmodules"
        }
    ]
    env_ev += list(env_data.get("matched_strings", []))

    evidence = {
        "vm_detection":       vm_ev,
        "anti_debugging":     dbg_ev,
        "timing_check":       tm_ev,
        "environment_check":  env_ev,
        "process_check":      proc_ev,
        "suspicious_imports": susp_imports,
    }

    schema = {
        "schema_version": "1.0",
        "analysis_type": "static",
        "sample_id": sample_id,
        "sample_name": finfo.get("filename", ""),
        "sha256": finfo.get("sha256", ""),
        "file_size": finfo.get("file_size", 0),
        "valid_pe": bool(finfo.get("is_valid_pe", False)),
        "sections": pe_sum.get("num_sections", 0),
        "imports": pe_sum.get("total_imported_functions", 0),
        "packed": bool(pe_sum.get("packing_heuristic", {}).get("is_packed", False)),
        "static_indicators": static_indicators,
        "evidence": evidence,
        "static_risk_score": risk.get("static_risk_score", 0.0),
        "static_risk_level": risk.get("static_risk_level", "LOW"),
    }

    return schema


def export_static_features(filepath: str, output_dir: str, sample_id: str) -> None:
    """
    Run analysis, print CLI summary (unchanged), then write shared schema JSON.
    """
    print(f"\n[*] Analyzing: {filepath}")
    result = analyze_file(filepath)

    # ── Existing terminal output (fully preserved) ──────────────────────────
    print_cli_summary(result["report"])

    # ── Build shared schema from real results ────────────────────────────────
    schema = build_shared_schema(
        report=result["report"],
        raw_pe=result["raw_pe"],
        sample_id=sample_id,
    )

    # ── Write to output/static_features.json ────────────────────────────────
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "static_features.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=4)

    print(f"[+] Shared schema written to: {out_path}")
    print(f"    SHA-256     : {schema['sha256']}")
    print(f"    Risk        : {schema['static_risk_score']}/100 [{schema['static_risk_level']}]")
    print(f"    Indicators  : {sum(1 for v in schema['static_indicators'].values() if v)} of "
          f"{len(schema['static_indicators'])} triggered")

    # Quick validation
    with open(out_path, "r", encoding="utf-8") as f:
        _check = json.load(f)
    assert _check["sha256"] == schema["sha256"], "SHA-256 round-trip mismatch!"
    print(f"[+] JSON validated OK.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Static Analyzer — Single-Sample Shared Schema Exporter"
    )
    parser.add_argument(
        "--file", "-f", required=True,
        help="Path to the PE file to analyze (e.g. samples/sample.exe)"
    )
    parser.add_argument(
        "--output-dir", "-o", default="output",
        help="Output directory for static_features.json (default: output)"
    )
    parser.add_argument(
        "--sample-id", "-s", default="S001",
        help="Consistent sample identifier shared across Person 1, 2, 3 (default: S001)"
    )
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[-] File not found: {args.file}")
        sys.exit(1)

    export_static_features(
        filepath=os.path.abspath(args.file),
        output_dir=args.output_dir,
        sample_id=args.sample_id,
    )


if __name__ == "__main__":
    main()
