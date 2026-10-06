"""
Deterministic Matching Engine for Sections and Functions
"""

from typing import Any, Dict, List, Set, Tuple

from provenanceguard.analyzers.elf.models import ELFSectionInfo
from provenanceguard.core.verification.models import (
    FunctionMatchKey,
    FunctionMetadata,
    SectionMatchKey,
    StructuralDelta,
)


class ArtifactMatcher:
    """
    Deterministic matching engine for section headers and function symbols.
    Calculates structural section deltas, renames, reordering, and symbol correlations.
    """

    @staticmethod
    def compare_sections(
        ref_sections: List[ELFSectionInfo],
        target_sections: List[ELFSectionInfo],
    ) -> List[StructuralDelta]:
        """
        Compares reference and target sections deterministically.
        Uses SectionMatchKey (name, section_type) as primary identity key.
        Uses secondary correlation (type, flags, size, content_digest) for single-candidate renames.
        Determines reordering based on section index comparison.
        """
        deltas: List[StructuralDelta] = []

        ref_map: Dict[Tuple[str, int], ELFSectionInfo] = {
            SectionMatchKey(name=s.name, section_type=s.section_type).key_tuple(): s
            for s in ref_sections
        }
        target_map: Dict[Tuple[str, int], ELFSectionInfo] = {
            SectionMatchKey(name=s.name, section_type=s.section_type).key_tuple(): s
            for s in target_sections
        }

        ref_matched_keys: Set[Tuple[str, int]] = set()
        target_matched_keys: Set[Tuple[str, int]] = set()

        # 1. Primary Match by (name, section_type)
        for key_tuple, ref_sec in ref_map.items():
            if key_tuple in target_map:
                ref_matched_keys.add(key_tuple)
                target_matched_keys.add(key_tuple)
                target_sec = target_map[key_tuple]

                # Check index reordering
                if ref_sec.index != target_sec.index:
                    deltas.append(
                        StructuralDelta(
                            delta_type="SECTION_REORDERED",
                            section_name=ref_sec.name,
                            details=(
                                f"Section '{ref_sec.name}' index shifted "
                                f"from {ref_sec.index} to {target_sec.index}."
                            ),
                            old_value=ref_sec.index,
                            new_value=target_sec.index,
                        )
                    )

                # Check size change
                if ref_sec.size != target_sec.size:
                    deltas.append(
                        StructuralDelta(
                            delta_type="SECTION_SIZE_CHANGED",
                            section_name=ref_sec.name,
                            details=(
                                f"Section '{ref_sec.name}' size changed "
                                f"from {ref_sec.size} to {target_sec.size} bytes."
                            ),
                            old_value=ref_sec.size,
                            new_value=target_sec.size,
                        )
                    )

                # Check flags change
                if ref_sec.flags != target_sec.flags:
                    deltas.append(
                        StructuralDelta(
                            delta_type="SECTION_FLAGS_CHANGED",
                            section_name=ref_sec.name,
                            details=(
                                f"Section '{ref_sec.name}' flags changed "
                                f"from {hex(ref_sec.flags)} to {hex(target_sec.flags)}."
                            ),
                            old_value=ref_sec.flags,
                            new_value=target_sec.flags,
                        )
                    )

                # Check content digest change
                if ref_sec.section_digest and target_sec.section_digest:
                    if ref_sec.section_digest != target_sec.section_digest:
                        deltas.append(
                            StructuralDelta(
                                delta_type="SECTION_CONTENT_CHANGED",
                                section_name=ref_sec.name,
                                details=f"Section '{ref_sec.name}' SHA-256 digest changed.",
                                old_value=ref_sec.section_digest,
                                new_value=target_sec.section_digest,
                            )
                        )

        # Unmatched sections
        unmatched_ref = [s for k, s in ref_map.items() if k not in ref_matched_keys]
        unmatched_target = [s for k, s in target_map.items() if k not in target_matched_keys]

        # 2. Secondary Rename Correlation
        # Match candidates by (type, flags, size, digest) when digest is present
        renamed_ref_sec: Set[int] = set()
        renamed_target_sec: Set[int] = set()

        for r_sec in unmatched_ref:
            if not r_sec.section_digest:
                continue
            candidates = [
                t_sec
                for t_sec in unmatched_target
                if t_sec.index not in renamed_target_sec
                and t_sec.section_type == r_sec.section_type
                and t_sec.flags == r_sec.flags
                and t_sec.size == r_sec.size
                and t_sec.section_digest == r_sec.section_digest
            ]

            # Rule: Require EXACTLY ONE deterministic candidate to represent as SECTION_RENAMED
            if len(candidates) == 1:
                t_sec = candidates[0]
                renamed_ref_sec.add(r_sec.index)
                renamed_target_sec.add(t_sec.index)
                deltas.append(
                    StructuralDelta(
                        delta_type="SECTION_RENAMED",
                        section_name=t_sec.name,
                        details=f"Section '{r_sec.name}' renamed to '{t_sec.name}'.",
                        old_value=r_sec.name,
                        new_value=t_sec.name,
                    )
                )

        # Remaining unmatched are SECTION_REMOVED and SECTION_ADDED
        for r_sec in unmatched_ref:
            if r_sec.index not in renamed_ref_sec:
                deltas.append(
                    StructuralDelta(
                        delta_type="SECTION_REMOVED",
                        section_name=r_sec.name,
                        details=f"Section '{r_sec.name}' removed in target artifact.",
                        old_value=r_sec.name,
                        new_value=None,
                    )
                )

        for t_sec in unmatched_target:
            if t_sec.index not in renamed_target_sec:
                deltas.append(
                    StructuralDelta(
                        delta_type="SECTION_ADDED",
                        section_name=t_sec.name,
                        details=f"New section '{t_sec.name}' added in target artifact.",
                        old_value=None,
                        new_value=t_sec.name,
                    )
                )

        return deltas

    @staticmethod
    def build_function_map(
        symbols: List[Any],
    ) -> Dict[Tuple[str, str, str], FunctionMetadata]:
        """
        Builds function map indexed by FunctionMatchKey (name, section_name, binding).
        Only includes STT_FUNC symbols.
        """
        func_map: Dict[Tuple[str, str, str], FunctionMetadata] = {}
        for s in symbols:
            # Handle both ELFSymbolInfo model objects and dicts
            sym_type = getattr(s, "symbol_type", None) or (
                s.get("symbol_type") if isinstance(s, dict) else None
            )
            if sym_type != "STT_FUNC":
                continue

            name = getattr(s, "name", None) or (s.get("name") if isinstance(s, dict) else "")
            sec_idx = getattr(s, "section_index", None) or (
                s.get("section_index") if isinstance(s, dict) else 0
            )
            sec_name = getattr(s, "section_name", None) or (
                s.get("section_name") if isinstance(s, dict) else ""
            )
            binding = getattr(s, "binding", None) or (
                s.get("binding") if isinstance(s, dict) else "STB_GLOBAL"
            )
            offset = getattr(s, "offset", None) or (s.get("offset") if isinstance(s, dict) else 0)
            size = getattr(s, "size", None) or (s.get("size") if isinstance(s, dict) else 0)
            address = getattr(s, "address", None) or (
                s.get("address") if isinstance(s, dict) else 0
            )

            match_key = FunctionMatchKey(
                name=name, section_name=sec_name, binding=binding
            ).key_tuple()
            func_map[match_key] = FunctionMetadata(
                name=name,
                section_index=sec_idx,
                section_name=sec_name,
                symbol_type=sym_type,
                binding=binding,
                offset=offset,
                size=size,
                address=address,
            )
        return func_map
