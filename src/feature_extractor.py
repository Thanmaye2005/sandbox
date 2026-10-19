"""Feature Extractor Module
Converts raw PE parsing data, string analysis, and anti-analysis indicator hits
into structured formats specifically tailored for Person 3's Detection Engine:
1. Explainable Hierarchical JSON Report
2. Flat Tabular Feature Vector (for CSV dataset export & ML scoring)
"""

import os
from typing import Dict, Any, List


SUSPICIOUS_SECTION_NAMES = {
    ".upx0", ".upx1", ".upx2", ".aspack", ".themida", ".vmp0", ".vmp1",
    ".packer", ".pack", ".mpress", ".nsp", ".petite", ".fsg"
}


class FeatureExtractor:
    """Transforms raw static analysis outputs into structured features and risk scores."""

    def __init__(
        self,
        filepath: str,
        pe_data: Dict[str, Any],
        string_data: Dict[str, Any],
        anti_analysis_data: Dict[str, Any],
    ):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.pe_data = pe_data
        self.string_data = string_data
        self.anti_analysis_data = anti_analysis_data

    def _evaluate_packing_heuristic(self) -> Dict[str, Any]:
        """Detect packed or encrypted binaries via entropy and section naming."""
        sections = self.pe_data.get("sections", [])
        suspicious_names = []
        high_entropy_sections = []

        for sec in sections:
            name = sec.get("name", "").lower()
            entropy = sec.get("entropy", 0.0)
            if any(s in name for s in SUSPICIOUS_SECTION_NAMES):
                suspicious_names.append(name)
            if entropy >= 7.0:
                high_entropy_sections.append({
                    "name": sec.get("name"),
                    "entropy": entropy,
                    "raw_size": sec.get("raw_size"),
                })

        # Check overlay entropy
        overlay_info = self.pe_data.get("overlay", {})
        has_high_entropy_overlay = (
            overlay_info.get("has_overlay", False)
            and overlay_info.get("overlay_entropy", 0.0) >= 7.0
            and overlay_info.get("overlay_size", 0) >= 1024
        )

        # Check packer string artifacts
        packer_strings_found = []
        all_strings = self.string_data.get("all_unique_strings", [])
        for s in all_strings:
            s_lower = s.lower()
            if any(p in s_lower for p in [".upx0", ".upx1", "upx!", "aspack", "themida", "vprotect"]):
                packer_strings_found.append(s[:30])

        meta = self.pe_data.get("metadata", {})
        file_entropy = meta.get("file_entropy", 0.0)

        is_packed = bool(
            suspicious_names
            or len(high_entropy_sections) > 0
            or has_high_entropy_overlay
            or len(packer_strings_found) > 0
            or file_entropy >= 7.2
        )

        return {
            "is_packed": is_packed,
            "suspicious_section_names": suspicious_names,
            "high_entropy_sections": high_entropy_sections,
            "has_high_entropy_overlay": has_high_entropy_overlay,
            "packer_strings": list(dict.fromkeys(packer_strings_found))[:5],
            "file_entropy": file_entropy,
        }

    def _compute_preliminary_risk(self) -> Dict[str, Any]:
        """Calculates a baseline static risk score (0 - 100) and risk level."""
        score = 0.0
        reasons = []

        # Anti-analysis indicators scoring
        aa_summary = self.anti_analysis_data.get("summary", {})
        vm = self.anti_analysis_data.get("vm_detection", {})
        dbg = self.anti_analysis_data.get("debugger_detection", {})
        env = self.anti_analysis_data.get("environment_checks", {})
        tm = self.anti_analysis_data.get("timing_checks", {})

        if vm.get("detected"):
            score += 25.0
            reasons.append("VM / Hypervisor evasion indicators detected")
        if dbg.get("detected"):
            score += 25.0
            reasons.append("Anti-debugging techniques detected")
        if env.get("detected"):
            score += 15.0
            reasons.append("Environment / Sandbox fingerprinting checks detected")
        if tm.get("detected"):
            score += 15.0
            reasons.append("Timing manipulation / delay checks detected")

        # Packing / Entropy scoring
        packing = self._evaluate_packing_heuristic()
        if packing["is_packed"]:
            score += 20.0
            reasons.append("Suspicious section entropy or known packer detected")

        score = min(100.0, score)

        if score >= 60.0:
            level = "HIGH"
        elif score >= 30.0:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "static_risk_score": score,
            "static_risk_level": level,
            "risk_factors": reasons,
        }

    def to_explainable_json(self) -> Dict[str, Any]:
        """Generate structured explainable report directly usable by Person 3."""
        packing = self._evaluate_packing_heuristic()
        risk = self._compute_preliminary_risk()
        meta = self.pe_data.get("metadata", {})
        sec_stats = self.pe_data.get("section_stats", {})
        imp_stats = self.pe_data.get("import_stats", {})

        return {
            "file_info": {
                "filename": self.filename,
                "filepath": self.filepath,
                "file_size": meta.get("file_size"),
                "md5": meta.get("md5"),
                "sha1": meta.get("sha1"),
                "sha256": meta.get("sha256"),
                "is_valid_pe": meta.get("is_valid_pe"),
                "entry_point": meta.get("entry_point"),
                "subsystem": meta.get("subsystem"),
            },
            "pe_summary": {
                "num_sections": sec_stats.get("count", 0),
                "max_section_entropy": sec_stats.get("max_entropy", 0.0),
                "avg_section_entropy": sec_stats.get("avg_entropy", 0.0),
                "has_high_entropy_section": sec_stats.get("has_high_entropy_section", False),
                "total_dlls": imp_stats.get("total_dlls", 0),
                "total_imported_functions": imp_stats.get("total_functions", 0),
                "packing_heuristic": packing,
            },
            "strings_summary": {
                "total_strings": self.string_data.get("total_strings_count", 0),
                "unique_strings": self.string_data.get("unique_strings_count", 0),
                "ip_count": len(self.string_data.get("extracted_ips", [])),
                "url_count": len(self.string_data.get("extracted_urls", [])),
                "registry_key_count": len(self.string_data.get("extracted_registry_keys", [])),
                "driver_references": self.string_data.get("extracted_drivers", []),
            },
            "anti_analysis_indicators": {
                "vm_detection": self.anti_analysis_data.get("vm_detection", {}),
                "debugger_detection": self.anti_analysis_data.get("debugger_detection", {}),
                "environment_checks": self.anti_analysis_data.get("environment_checks", {}),
                "timing_checks": self.anti_analysis_data.get("timing_checks", {}),
                "summary": self.anti_analysis_data.get("summary", {}),
            },
            "preliminary_assessment": risk,
        }

    def to_flat_feature_vector(self) -> Dict[str, Any]:
        """Generates flat dictionary for CSV row export and machine learning / scoring."""
        meta = self.pe_data.get("metadata", {})
        sec_stats = self.pe_data.get("section_stats", {})
        imp_stats = self.pe_data.get("import_stats", {})

        vm = self.anti_analysis_data.get("vm_detection", {})
        dbg = self.anti_analysis_data.get("debugger_detection", {})
        env = self.anti_analysis_data.get("environment_checks", {})
        tm = self.anti_analysis_data.get("timing_checks", {})
        aa_sum = self.anti_analysis_data.get("summary", {})

        packing = self._evaluate_packing_heuristic()
        risk = self._compute_preliminary_risk()

        return {
            "filename": self.filename,
            "sha256": meta.get("sha256", ""),
            "file_size": meta.get("file_size", 0),
            "is_valid_pe": 1 if meta.get("is_valid_pe") else 0,
            "num_sections": sec_stats.get("count", 0),
            "max_entropy": sec_stats.get("max_entropy", 0.0),
            "avg_entropy": sec_stats.get("avg_entropy", 0.0),
            "has_high_entropy_section": 1 if sec_stats.get("has_high_entropy_section") else 0,
            "total_imported_dlls": imp_stats.get("total_dlls", 0),
            "total_imported_functions": imp_stats.get("total_functions", 0),
            "total_strings": self.string_data.get("total_strings_count", 0),
            "unique_strings": self.string_data.get("unique_strings_count", 0),
            "ip_count": len(self.string_data.get("extracted_ips", [])),
            "url_count": len(self.string_data.get("extracted_urls", [])),
            "registry_key_count": len(self.string_data.get("extracted_registry_keys", [])),
            "anti_vm_detected": 1 if vm.get("detected") else 0,
            "anti_vm_api_count": vm.get("api_count", 0),
            "anti_vm_string_count": vm.get("string_count", 0),
            "anti_debug_detected": 1 if dbg.get("detected") else 0,
            "anti_debug_api_count": dbg.get("api_count", 0),
            "anti_debug_string_count": dbg.get("string_count", 0),
            "env_check_detected": 1 if env.get("detected") else 0,
            "env_check_api_count": env.get("api_count", 0),
            "env_check_string_count": env.get("string_count", 0),
            "timing_check_detected": 1 if tm.get("detected") else 0,
            "timing_check_api_count": tm.get("api_count", 0),
            "timing_check_string_count": tm.get("string_count", 0),
            "has_timing_pair": 1 if tm.get("has_timing_pair") else 0,
            "total_anti_analysis_indicators": aa_sum.get("total_indicators", 0),
            "categories_triggered_count": aa_sum.get("categories_triggered_count", 0),
            "is_packed": 1 if packing["is_packed"] else 0,
            "static_risk_score": risk["static_risk_score"],
            "static_risk_level": risk["static_risk_level"],
        }
