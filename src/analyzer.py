"""Main Static Analysis Engine CLI
Orchestrates PE parsing, string extraction, anti-analysis detection, and feature dataset generation.
"""

import os
import sys
import json
import csv
import argparse
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pe_parser import PEParser
from string_extractor import StringExtractor
from anti_analysis import AntiAnalysisDetector
from feature_extractor import FeatureExtractor


def analyze_file(filepath: str) -> Dict[str, Any]:
    """Perform full static analysis on a single executable."""
    parser = PEParser(filepath)
    pe_data = parser.parse_all()

    with open(filepath, "rb") as f:
        file_bytes = f.read()

    extractor = StringExtractor(file_bytes)
    string_data = extractor.analyze_strings()

    detector = AntiAnalysisDetector(
        imports=pe_data.get("imports", {}),
        strings=string_data.get("all_unique_strings", []),
    )
    anti_analysis_data = detector.analyze_all()

    feat_extractor = FeatureExtractor(
        filepath=filepath,
        pe_data=pe_data,
        string_data=string_data,
        anti_analysis_data=anti_analysis_data,
    )

    explainable_report = feat_extractor.to_explainable_json()
    flat_vector = feat_extractor.to_flat_feature_vector()

    return {
        "report": explainable_report,
        "features": flat_vector,
        "raw_pe": pe_data,
    }


def print_cli_summary(report: Dict[str, Any]) -> None:
    """Print readable summary of the analysis to stdout."""
    finfo = report["file_info"]
    pe = report["pe_summary"]
    aa = report["anti_analysis_indicators"]
    risk = report["preliminary_assessment"]

    print("=" * 65)
    print(f" STATIC ANALYSIS REPORT: {finfo['filename']}")
    print("=" * 65)
    print(f" File Size     : {finfo['file_size']} bytes")
    print(f" SHA256        : {finfo['sha256']}")
    print(f" Valid PE      : {'Yes' if finfo['is_valid_pe'] else 'No'}")
    print(f" Sections      : {pe['num_sections']} (Max Entropy: {pe['max_section_entropy']})")
    print(f" Imports       : {pe['total_imported_functions']} functions from {pe['total_dlls']} DLLs")
    print(f" Packed/Crypt  : {'Yes' if pe['packing_heuristic']['is_packed'] else 'No'}")
    print("-" * 65)
    print(" ANTI-ANALYSIS INDICATORS:")
    print(f"  [*] VM Detection       : {'DETECTED' if aa['vm_detection']['detected'] else 'Not Detected'}")
    if aa['vm_detection']['detected']:
        for ev in aa['vm_detection']['evidence']:
            print(f"      - {ev}")
    print(f"  [*] Debugger Detection : {'DETECTED' if aa['debugger_detection']['detected'] else 'Not Detected'}")
    if aa['debugger_detection']['detected']:
        for ev in aa['debugger_detection']['evidence']:
            print(f"      - {ev}")
    print(f"  [*] Environment Checks : {'DETECTED' if aa['environment_checks']['detected'] else 'Not Detected'}")
    if aa['environment_checks']['detected']:
        for ev in aa['environment_checks']['evidence']:
            print(f"      - {ev}")
    print(f"  [*] Timing Checks      : {'DETECTED' if aa['timing_checks']['detected'] else 'Not Detected'}")
    if aa['timing_checks']['detected']:
        for ev in aa['timing_checks']['evidence']:
            print(f"      - {ev}")
    print("-" * 65)
    print(f" STATIC RISK SCORE : {risk['static_risk_score']}/100 [{risk['static_risk_level']}]")
    if risk["risk_factors"]:
        for factor in risk["risk_factors"]:
            print(f"  * {factor}")
    print("=" * 65 + "\n")


def process_samples(filepaths: List[str], output_dir: str) -> None:
    """Analyze a batch of samples and write output JSON & CSV datasets."""
    os.makedirs(output_dir, exist_ok=True)
    all_reports: List[Dict[str, Any]] = []
    all_features: List[Dict[str, Any]] = []

    print(f"\nProcessing {len(filepaths)} sample(s)...")

    for fp in filepaths:
        try:
            res = analyze_file(fp)
            print_cli_summary(res["report"])
            all_reports.append(res["report"])
            all_features.append(res["features"])
        except Exception as e:
            print(f"[-] Error analyzing {fp}: {e}", file=sys.stderr)

    # 1. Save Explainable JSON Dataset for Person 3
    json_path = os.path.join(output_dir, "static_features.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(all_reports, f, indent=2)
    print(f"[+] Saved structured explainable JSON dataset to: {json_path}")

    # 2. Save Flat CSV Feature Vector Dataset for Person 3
    if all_features:
        csv_path = os.path.join(output_dir, "static_features.csv")
        keys = list(all_features[0].keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(all_features)
        print(f"[+] Saved tabular feature dataset to: {csv_path}")


def main():
    parser = argparse.ArgumentParser(description="Static PE Analyzer & Feature Extractor")
    parser.add_argument("--file", "-f", help="Path to single PE file to analyze")
    parser.add_argument("--dir", "-d", help="Directory of PE files to analyze")
    parser.add_argument("--output-dir", "-o", default="output", help="Output directory for reports and datasets")
    args = parser.parse_args()

    files_to_analyze: List[str] = []

    if args.file:
        if os.path.isfile(args.file):
            files_to_analyze.append(os.path.abspath(args.file))
        else:
            print(f"Error: File not found: {args.file}")
            sys.exit(1)
    elif args.dir:
        if os.path.isdir(args.dir):
            for root, _, filenames in os.walk(args.dir):
                for fn in filenames:
                    if fn.lower().endswith((".exe", ".dll", ".sys", ".bin")):
                        files_to_analyze.append(os.path.join(root, fn))
        else:
            print(f"Error: Directory not found: {args.dir}")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    if not files_to_analyze:
        print("No executable files found to analyze.")
        sys.exit(1)

    process_samples(files_to_analyze, args.output_dir)


if __name__ == "__main__":
    main()
