"""PE Parser Module
Extracts PE headers, sections, entropy, imports, exports, and hashes from PE binaries.
"""

import hashlib
import math
from typing import Dict, Any, List, Optional
import pefile


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0.0 - 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_hashes(file_bytes: bytes) -> Dict[str, str]:
    """Compute MD5, SHA1, and SHA256 hashes of the file."""
    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
    }


class PEParser:
    """Parses Portable Executable (PE) files using pefile."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        with open(filepath, "rb") as f:
            self.raw_data = f.read()
        self.pe: Optional[pefile.PE] = None
        self.parse_error: Optional[str] = None
        try:
            self.pe = pefile.PE(data=self.raw_data, fast_load=False)
        except Exception as e:
            self.parse_error = str(e)

    def is_valid_pe(self) -> bool:
        return self.pe is not None and self.parse_error is None

    def get_basic_metadata(self) -> Dict[str, Any]:
        hashes = calculate_hashes(self.raw_data)
        file_size = len(self.raw_data)
        file_entropy = calculate_entropy(self.raw_data)
        metadata: Dict[str, Any] = {
            "file_size": file_size,
            "file_entropy": file_entropy,
            "md5": hashes["md5"],
            "sha1": hashes["sha1"],
            "sha256": hashes["sha256"],
            "is_valid_pe": self.is_valid_pe(),
            "parse_error": self.parse_error,
        }

        if not self.is_valid_pe() or not self.pe:
            return metadata

        # File header & Optional header metadata
        file_header = getattr(self.pe, "FILE_HEADER", None)
        opt_header = getattr(self.pe, "OPTIONAL_HEADER", None)

        metadata.update({
            "machine": hex(file_header.Machine) if file_header else None,
            "number_of_sections": file_header.NumberOfSections if file_header else 0,
            "timestamp": file_header.TimeDateStamp if file_header else None,
            "characteristics": hex(file_header.Characteristics) if file_header else None,
            "entry_point": hex(opt_header.AddressOfEntryPoint) if opt_header else None,
            "image_base": hex(opt_header.ImageBase) if opt_header else None,
            "subsystem": opt_header.Subsystem if opt_header else None,
            "dll_characteristics": hex(opt_header.DllCharacteristics) if opt_header else None,
            "magic": hex(opt_header.Magic) if opt_header else None,
        })
        return metadata

    def get_sections(self) -> List[Dict[str, Any]]:
        """Parse PE sections, compute sizes and Shannon entropy."""
        sections = []
        if not self.is_valid_pe() or not self.pe:
            return sections

        for section in self.pe.sections:
            try:
                name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            except Exception:
                name = str(section.Name)

            sec_data = section.get_data()
            entropy = calculate_entropy(sec_data)

            sections.append({
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": entropy,
                "characteristics": hex(section.Characteristics),
                "is_writable": bool(section.Characteristics & 0x80000000),
                "is_executable": bool(section.Characteristics & 0x20000000),
                "is_readable": bool(section.Characteristics & 0x40000000),
            })
        return sections

    def get_imports(self) -> Dict[str, List[str]]:
        """Extract imported DLLs and functions."""
        imports_dict: Dict[str, List[str]] = {}
        if not self.is_valid_pe() or not self.pe:
            return imports_dict

        if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return imports_dict

        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = entry.dll.decode("utf-8", errors="ignore").lower()
            except Exception:
                dll_name = str(entry.dll).lower()

            funcs = []
            for imp in entry.imports:
                if imp.name:
                    try:
                        func_name = imp.name.decode("utf-8", errors="ignore")
                    except Exception:
                        func_name = str(imp.name)
                    funcs.append(func_name)
                elif imp.ordinal:
                    funcs.append(f"ord_{imp.ordinal}")
            imports_dict[dll_name] = funcs
        return imports_dict

    def get_exports(self) -> List[str]:
        """Extract exported function names."""
        exports: List[str] = []
        if not self.is_valid_pe() or not self.pe:
            return exports

        if not hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            return exports

        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                try:
                    exports.append(exp.name.decode("utf-8", errors="ignore"))
                except Exception:
                    exports.append(str(exp.name))
        return exports

    def parse_all(self) -> Dict[str, Any]:
        """Extract complete structured PE analysis report."""
        metadata = self.get_basic_metadata()
        sections = self.get_sections()
        imports = self.get_imports()
        exports = self.get_exports()

        entropies = [s["entropy"] for s in sections] if sections else [0.0]
        max_entropy = max(entropies) if entropies else 0.0
        avg_entropy = round(sum(entropies) / len(entropies), 4) if entropies else 0.0

        total_imported_functions = sum(len(funcs) for funcs in imports.values())

        # Check overlay (data appended after PE sections)
        overlay_offset = None
        overlay_size = 0
        overlay_entropy = 0.0
        if self.is_valid_pe() and self.pe:
            try:
                overlay_offset = self.pe.get_overlay_data_offset()
                if overlay_offset and overlay_offset < len(self.raw_data):
                    overlay_data = self.raw_data[overlay_offset:]
                    overlay_size = len(overlay_data)
                    overlay_entropy = calculate_entropy(overlay_data)
            except Exception:
                pass

        return {
            "metadata": metadata,
            "sections": sections,
            "section_stats": {
                "count": len(sections),
                "max_entropy": max_entropy,
                "avg_entropy": avg_entropy,
                "has_high_entropy_section": max_entropy > 7.0,
            },
            "overlay": {
                "has_overlay": overlay_size > 0,
                "overlay_size": overlay_size,
                "overlay_entropy": overlay_entropy,
            },
            "imports": imports,
            "import_stats": {
                "total_dlls": len(imports),
                "total_functions": total_imported_functions,
            },
            "exports": exports,
        }
