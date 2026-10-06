"""
OCI Container Image Static Analyzer implementing ArtifactAnalyzer interface.
"""

import io
import tarfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from provenanceguard.analyzers.base import (
    AnalyzerCapabilities,
    AnalyzerResult,
    ArtifactAnalyzer,
)
from provenanceguard.analyzers.elf.parser import StaticELFParser
from provenanceguard.analyzers.oci.oci_adapters import (
    DockerSaveAdapter,
    OCIError,
    OCIImageLayoutAdapter,
    OCIResourceExceededError,
)
from provenanceguard.analyzers.oci.oci_extraction import OCIHardenedExtractor, VirtualRootFS
from provenanceguard.analyzers.oci.oci_ingestion import OCIImageIngestor
from provenanceguard.analyzers.oci.oci_spec import (
    DOCKER_MANIFEST_MEDIA_TYPE,
    OCI_INDEX_MEDIA_TYPE,
    OCI_MANIFEST_MEDIA_TYPE,
    NormalizedOCIImage,
    Platform,
)
from provenanceguard.analyzers.oci.oci_whiteout import OCIWhiteoutProcessor

# Downstream Analysis Resource Limits
MAX_ANALYSIS_ELF_COUNT = 1000
MAX_ANALYSIS_ELF_BYTES = 500 * 1024 * 1024  # 500 MB
MAX_ANALYSIS_SBOM_COUNT = 100
MAX_ANALYSIS_METADATA_ENTRIES = 100_000
MAX_ANALYSIS_DURATION_SECONDS = 120.0


class OCIContainerAnalyzer(ArtifactAnalyzer):
    """
    Static analyzer for OCI Image Layout archives and Docker Save archives.
    Implements ArtifactAnalyzer abstract interface. Reuses StaticELFParser.
    """

    def supports(self, media_type: str) -> bool:
        """Returns True if media_type is an OCI or Docker archive media-type."""
        supported = {
            OCI_MANIFEST_MEDIA_TYPE,
            OCI_INDEX_MEDIA_TYPE,
            DOCKER_MANIFEST_MEDIA_TYPE,
            "application/vnd.oci.image.layout.v1+tar",
            "application/x-tar",
            "application/tar",
            "application/octet-stream",
        }
        return (
            media_type in supported
            or media_type.startswith("application/vnd.oci.")
            or media_type.startswith("application/vnd.docker.")
        )

    def capabilities(self) -> AnalyzerCapabilities:
        """Returns capabilities of OCI Container Analyzer."""
        return AnalyzerCapabilities(
            supports_binary_diff=True,
            supports_symbol_table=True,
            supports_sbom_parsing=True,
            supported_architectures=["x86_64", "aarch64", "i386", "ARM", "RISC-V"],
        )

    def analyze(
        self,
        artifact_path: Path,
        platform_selector: Optional[Platform] = None,
        requested_docker_image: Optional[str] = None,
    ) -> AnalyzerResult:
        """
        Statically analyzes an OCI / Docker archive file or directory without container execution.
        """
        start_time = time.time()
        blobs = self._load_archive_blobs(artifact_path)

        # Determine format adapter
        normalized_image: NormalizedOCIImage
        if "oci-layout" in blobs or "index.json" in blobs:
            adapter = OCIImageLayoutAdapter()
            normalized_image = adapter.parse_layout(blobs, platform_selector)
        elif "manifest.json" in blobs:
            adapter = DockerSaveAdapter()
            normalized_image = adapter.parse_archive(blobs, requested_docker_image)
        else:
            raise OCIError(
                "Unrecognized archive format: missing 'index.json', 'oci-layout', or 'manifest.json'"
            )

        # Ingestion integrity verification
        ingestor = OCIImageIngestor()
        ingestor.verify_integrity(normalized_image)

        # Extraction into VirtualRootFS
        extractor = OCIHardenedExtractor()
        virtual_fs = extractor.extract_layers(normalized_image)

        # Whiteout processing
        whiteout_proc = OCIWhiteoutProcessor()
        whiteout_proc.apply_whiteouts(virtual_fs)

        # Downstream analysis bounds check & scanning
        return self._scan_virtual_rootfs(virtual_fs, normalized_image, start_time)

    def _load_archive_blobs(self, path: Path) -> Dict[str, bytes]:
        """Loads tar archive entries or filesystem directory files into bytes dictionary."""
        blobs: Dict[str, bytes] = {}

        if path.is_dir():
            for p in path.rglob("*"):
                if p.is_file():
                    rel_path = p.relative_to(path).as_posix()
                    blobs[rel_path] = p.read_bytes()
                    # Also map blobs/sha256/<hex> directly to sha256:<hex>
                    if rel_path.startswith("blobs/sha256/"):
                        hex_val = p.name
                        blobs[f"sha256:{hex_val}"] = p.read_bytes()
        elif path.is_file():
            try:
                with tarfile.open(path, "r:*") as tar:
                    for member in tar.getmembers():
                        if member.isfile():
                            f_obj = tar.extractfile(member)
                            content = f_obj.read() if f_obj else b""
                            blobs[member.name] = content
                            if member.name.startswith("blobs/sha256/"):
                                hex_val = posixpath_basename(member.name)
                                blobs[f"sha256:{hex_val}"] = content
            except Exception as e:
                raise OCIError(f"Failed to read tar archive '{path}': {str(e)}") from e
        else:
            raise OCIError(f"Artifact path '{path}' does not exist")

        return blobs

    def _scan_virtual_rootfs(
        self,
        virtual_fs: VirtualRootFS,
        normalized_image: NormalizedOCIImage,
        start_time: float,
    ) -> AnalyzerResult:
        """Scans VirtualRootFS while enforcing downstream resource limits."""
        sections_out: List[Dict[str, Any]] = []
        functions_out: List[Dict[str, Any]] = []
        imports_out: Set[str] = set()
        warnings_out: List[str] = []

        elf_count = 0
        aggregate_elf_bytes = 0
        sbom_count = 0
        total_metadata_entries = (
            len(virtual_fs.files) + len(virtual_fs.symlinks) + len(virtual_fs.directories)
        )

        if total_metadata_entries > MAX_ANALYSIS_METADATA_ENTRIES:
            raise OCIResourceExceededError(
                f"Total metadata entries ({total_metadata_entries}) exceeds analysis limit ({MAX_ANALYSIS_METADATA_ENTRIES})"
            )

        architecture = normalized_image.config.architecture

        for rel_path, vfile in virtual_fs.files.items():
            # Check duration budget
            elapsed = time.time() - start_time
            if elapsed > MAX_ANALYSIS_DURATION_SECONDS:
                raise OCIResourceExceededError(
                    f"Downstream analysis duration ({elapsed:.2f}s) exceeded budget ({MAX_ANALYSIS_DURATION_SECONDS}s)"
                )

            # Check if file is an ELF binary (magic bytes \x7fELF)
            if vfile.content.startswith(b"\x7fELF"):
                elf_count += 1
                aggregate_elf_bytes += vfile.size

                if elf_count > MAX_ANALYSIS_ELF_COUNT:
                    raise OCIResourceExceededError(
                        f"Analyzed ELF count ({elf_count}) exceeds limit ({MAX_ANALYSIS_ELF_COUNT})"
                    )

                if aggregate_elf_bytes > MAX_ANALYSIS_ELF_BYTES:
                    raise OCIResourceExceededError(
                        f"Aggregate ELF bytes ({aggregate_elf_bytes}) exceeds limit ({MAX_ANALYSIS_ELF_BYTES})"
                    )

                try:
                    stream = io.BytesIO(vfile.content)
                    parser = StaticELFParser(stream)
                    header = parser.parse_header()
                    sec_list, _ = parser.parse_sections(header)
                    sym_list = parser.parse_symbols(header, sec_list)
                    dyn_imports = parser.parse_dynamic_imports(header, sec_list)

                    for sec in sec_list:
                        sections_out.append(
                            {
                                "path": rel_path,
                                "section_name": sec.name,
                                "size": sec.size,
                                "digest": sec.section_digest,
                            }
                        )

                    for sym in sym_list:
                        functions_out.append(
                            {
                                "path": rel_path,
                                "name": sym.name,
                                "binding": sym.binding,
                                "symbol_type": sym.symbol_type,
                            }
                        )

                    for imp in dyn_imports:
                        imports_out.add(imp)

                except Exception as e:
                    warnings_out.append(f"Failed to parse ELF binary '{rel_path}': {str(e)}")

            # Check if file is an embedded SBOM
            filename_lower = posixpath_basename(rel_path).lower()
            if filename_lower in (
                "spdx.json",
                "bom.json",
                "sbom.spdx",
                "cyclonedx.json",
            ) or filename_lower.endswith(".spdx.json"):
                sbom_count += 1
                if sbom_count > MAX_ANALYSIS_SBOM_COUNT:
                    raise OCIResourceExceededError(
                        f"Analyzed SBOM count ({sbom_count}) exceeds limit ({MAX_ANALYSIS_SBOM_COUNT})"
                    )

        return AnalyzerResult(
            artifact_type="OCI_IMAGE",
            architecture=architecture,
            bits=64 if "64" in architecture else 32,
            sections=sections_out,
            functions=functions_out,
            imports=sorted(list(imports_out)),
            warnings=warnings_out,
        )


def posixpath_basename(path: str) -> str:
    import posixpath

    return posixpath.basename(path)
