"""
SPDX & CycloneDX SBOM Document Parser and Normalizer.
Enforces safe 6-stage processing pipeline and resource limits.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from provenanceguard.analyzers.base import AnalyzerCapabilities, AnalyzerResult, ArtifactAnalyzer
from provenanceguard.core.artifacts.detector import detect_media_type_from_bytes
from provenanceguard.core.domain.enums import MediaType
from provenanceguard.core.verification.sbom_models import (
    ChecksumEvidence,
    IdentityStatus,
    LicenseEvidence,
    PackageEvidence,
    PackageIdentity,
    SBOMInventoryCompleteness,
    SBOMReport,
)

# Phase 7 Resource Limits
MAX_SBOM_SIZE = 5 * 1024 * 1024  # 5 MiB
MAX_COMPONENTS_COUNT = 5000
MAX_JSON_DEPTH = 10
MAX_EXTENSION_DEPTH = 5
MAX_EXTENSION_KEYS = 50
MAX_EXTENSION_ARRAY_LEN = 100
MAX_EXTENSION_STRING_SIZE = 16384  # 16 KiB


class SBOMParserError(Exception):
    """Exception raised for SBOM parsing and validation errors."""

    def __init__(self, message: str, error_code: str = "INVALID_DOCUMENT"):
        super().__init__(message)
        self.message = message
        self.error_code = error_code


def validate_json_structural_depth(raw_text: str, max_depth: int = MAX_JSON_DEPTH) -> None:
    """
    JSON-aware structural depth pre-scanner.
    Correctly handles string literal bounds, escaped quotes (\\"), escaped backslashes (\\\\),
    and ignore brackets inside strings.
    """
    in_string = False
    escape_next = False
    depth = 0

    for char in raw_text:
        if escape_next:
            escape_next = False
            continue

        if char == "\\":
            if in_string:
                escape_next = True
            continue

        if char == '"':
            in_string = not in_string
            continue

        if not in_string:
            if char in ("{", "["):
                depth += 1
                if depth > max_depth:
                    raise SBOMParserError(
                        f"JSON structural depth ({depth}) exceeds limit ({max_depth})",
                        error_code="RESOURCE_LIMIT_EXCEEDED",
                    )
            elif char in ("}", "]"):
                if depth > 0:
                    depth -= 1


def sanitize_raw_extension_data(data: Dict[str, Any], current_depth: int = 1) -> Dict[str, Any]:
    """
    Validates and bounds raw extension data to prevent resource-limit bypass.
    """
    if current_depth > MAX_EXTENSION_DEPTH:
        return {}

    sanitized: Dict[str, Any] = {}
    count = 0

    for key, val in data.items():
        if count >= MAX_EXTENSION_KEYS:
            break
        count += 1

        clean_key = str(key)[:256]

        if isinstance(val, (int, float, bool)) or val is None:
            sanitized[clean_key] = val
        elif isinstance(val, str):
            sanitized[clean_key] = val[:MAX_EXTENSION_STRING_SIZE]
        elif isinstance(val, dict):
            sanitized[clean_key] = sanitize_raw_extension_data(val, current_depth + 1)
        elif isinstance(val, list):
            clean_list = []
            for item in val[:MAX_EXTENSION_ARRAY_LEN]:
                if isinstance(item, (int, float, bool)) or item is None:
                    clean_list.append(item)
                elif isinstance(item, str):
                    clean_list.append(item[:MAX_EXTENSION_STRING_SIZE])
                elif isinstance(item, dict):
                    clean_list.append(sanitize_raw_extension_data(item, current_depth + 1))
            sanitized[clean_key] = clean_list

    return sanitized


class SBOMAnalyzer(ArtifactAnalyzer):
    """
    ArtifactAnalyzer implementation for SPDX and CycloneDX SBOM documents.
    """

    def supports(self, media_type: str) -> bool:
        """Returns True if the analyzer supports the given media_type string or enum."""
        supported_types = {
            MediaType.SPDX_JSON.value,
            MediaType.CYCLONEDX_JSON.value,
            "spdx_json",
            "cyclonedx_json",
            "application/spdx+json",
            "application/vnd.cyclonedx+json",
        }
        return str(media_type).lower() in supported_types

    def capabilities(self) -> AnalyzerCapabilities:
        return AnalyzerCapabilities(
            supports_binary_diff=False,
            supports_symbol_table=False,
            supports_sbom_parsing=True,
            supported_architectures=["ALL"],
        )

    def analyze(self, artifact_path: Path) -> AnalyzerResult:
        """Statically analyzes an SBOM artifact file."""
        if not artifact_path.exists():
            raise SBOMParserError(f"Artifact file not found: {artifact_path}")

        raw_bytes = artifact_path.read_bytes()
        report = self.parse_sbom(raw_bytes)

        # Convert report packages into AnalyzerResult format
        pkgs_summary = [
            {
                "name": p.name,
                "version": p.version,
                "purl": p.purl,
                "canonical_key": p.identity.canonical_key,
                "supplier": p.supplier,
            }
            for p in report.packages
        ]

        return AnalyzerResult(
            artifact_type=report.format_type,
            functions=pkgs_summary,
            warnings=report.warnings,
        )

    def parse_sbom(
        self, raw_bytes: bytes, expected_media_type: Optional[MediaType] = None
    ) -> SBOMReport:
        """
        Executes the safe 7-stage processing pipeline on raw SBOM document bytes.
        """
        # Stage 1: Raw Byte-Size Limit
        if len(raw_bytes) > MAX_SBOM_SIZE:
            raise SBOMParserError(
                f"SBOM payload size ({len(raw_bytes)} bytes) exceeds limit ({MAX_SBOM_SIZE} bytes)",
                error_code="RESOURCE_LIMIT_EXCEEDED",
            )

        if not raw_bytes or not raw_bytes.strip():
            raise SBOMParserError("Empty SBOM payload", error_code="INVALID_DOCUMENT")

        # Stage 2: UTF-8 BOM Handling
        clean_bytes = raw_bytes
        if clean_bytes.startswith(b"\xef\xbb\xbf"):
            clean_bytes = clean_bytes[3:]

        # Stage 3: UTF-8 Decoding Validation
        try:
            raw_text = clean_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise SBOMParserError(
                f"Invalid UTF-8 encoding in SBOM payload: {str(e)}",
                error_code="INVALID_DOCUMENT",
            ) from e

        # Stage 4: JSON-Aware Bounded Structural Depth Pre-Scanner
        validate_json_structural_depth(raw_text, max_depth=MAX_JSON_DEPTH)

        # Stage 5: JSON Parsing
        try:
            doc = json.loads(raw_text)
        except json.JSONDecodeError as e:
            raise SBOMParserError(
                f"Malformed JSON payload: {str(e)}", error_code="INVALID_DOCUMENT"
            ) from e

        if not isinstance(doc, dict):
            raise SBOMParserError(
                "Root JSON document must be an object", error_code="INVALID_DOCUMENT"
            )

        # Detect Spec Format & Version
        media_type = expected_media_type or detect_media_type_from_bytes(raw_bytes)

        if "spdxVersion" in doc or media_type == MediaType.SPDX_JSON:
            return self._parse_spdx(doc)
        elif doc.get("bomFormat") == "CycloneDX" or media_type == MediaType.CYCLONEDX_JSON:
            return self._parse_cyclonedx(doc)
        else:
            raise SBOMParserError(
                "Unrecognized SBOM format or missing root document spec markers",
                error_code="UNSUPPORTED_VERSION",
            )

    def _parse_spdx(self, doc: Dict[str, Any]) -> SBOMReport:
        """Parses and normalizes SPDX v2.2 / v2.3 JSON document."""
        spdx_version = str(doc.get("spdxVersion", ""))
        if spdx_version not in ("SPDX-2.2", "SPDX-2.3"):
            raise SBOMParserError(
                f"Unsupported SPDX version '{spdx_version}'. Supported: SPDX-2.2, SPDX-2.3",
                error_code="UNSUPPORTED_VERSION",
            )

        packages_raw = doc.get("packages")
        if not isinstance(packages_raw, list):
            raise SBOMParserError(
                "SPDX document missing 'packages' array", error_code="SCHEMA_VALIDATION_FAILED"
            )

        # Stage 6: Component Count Validation
        if len(packages_raw) > MAX_COMPONENTS_COUNT:
            raise SBOMParserError(
                f"SPDX package count ({len(packages_raw)}) exceeds limit ({MAX_COMPONENTS_COUNT})",
                error_code="RESOURCE_LIMIT_EXCEEDED",
            )

        parsed_packages: List[PackageEvidence] = []
        warnings: List[str] = []
        observed_keys: Dict[str, int] = {}

        for pkg in packages_raw:
            if not isinstance(pkg, dict):
                continue

            name = str(pkg.get("name", "")).strip()
            if not name:
                continue

            version = pkg.get("versionInfo")
            version_str = str(version).strip() if version is not None else None

            supplier = pkg.get("supplier")
            supplier_str = str(supplier).strip() if supplier is not None else None

            # Extract PURL and Checksums
            purl_str = None
            checksums: List[ChecksumEvidence] = []
            ext_refs = pkg.get("externalRefs", [])

            if isinstance(ext_refs, list):
                for ref in ext_refs:
                    if isinstance(ref, dict):
                        if (
                            ref.get("referenceType") == "purl"
                            or ref.get("referenceCategory") == "PACKAGE-MANAGER"
                        ):
                            purl_candidate = ref.get("referenceLocator")
                            if purl_candidate and str(purl_candidate).startswith("pkg:"):
                                purl_str = str(purl_candidate).strip()

            # Parse Checksums
            chk_raw = pkg.get("checksums", [])
            if isinstance(chk_raw, list):
                for c in chk_raw:
                    if isinstance(c, dict) and "algorithm" in c and "checksumValue" in c:
                        alg_norm = ChecksumEvidence.normalize_algorithm(str(c["algorithm"]))
                        digest = str(c["checksumValue"]).strip().lower()
                        checksums.append(
                            ChecksumEvidence(normalized_algorithm=alg_norm, digest=digest)
                        )

            # Deduplicate checksums deterministically
            checksums = sorted(
                list(set(checksums)), key=lambda c: (c.normalized_algorithm, c.digest)
            )

            # Parse Licenses
            lic_declared = pkg.get("licenseDeclared")
            lic_concluded = pkg.get("licenseConcluded")
            lic_info = pkg.get("licenseInfoFromFiles", [])

            is_none = str(lic_declared).upper() == "NONE" or str(lic_concluded).upper() == "NONE"
            is_noassertion = (
                str(lic_declared).upper() == "NOASSERTION"
                or str(lic_concluded).upper() == "NOASSERTION"
            )

            licenses = LicenseEvidence(
                license_declared=str(lic_declared)
                if lic_declared and not is_none and not is_noassertion
                else None,
                license_concluded=str(lic_concluded)
                if lic_concluded and not is_none and not is_noassertion
                else None,
                license_info_from_files=[str(x) for x in lic_info]
                if isinstance(lic_info, list)
                else [],
                is_none=is_none,
                is_noassertion=is_noassertion,
            )

            # Identity Resolution
            identity = None
            if purl_str:
                identity = PackageIdentity.from_purl(purl_str)

            if identity is None:
                identity = PackageIdentity.from_name_supplier(name, supplier_str)

            # Track duplicate / ambiguous identity status
            c_key = identity.canonical_key
            observed_keys[c_key] = observed_keys.get(c_key, 0) + 1
            status = (
                IdentityStatus.UNIQUE if observed_keys[c_key] == 1 else IdentityStatus.DUPLICATE
            )

            # Bounded raw_extension_data
            ext_data = {
                k: v
                for k, v in pkg.items()
                if k
                not in (
                    "name",
                    "versionInfo",
                    "supplier",
                    "licenseDeclared",
                    "licenseConcluded",
                    "licenseInfoFromFiles",
                    "checksums",
                    "externalRefs",
                )
            }
            sanitized_ext = sanitize_raw_extension_data(ext_data)

            parsed_packages.append(
                PackageEvidence(
                    source_format="SPDX",
                    source_version=spdx_version,
                    source_identifier=str(pkg.get("SPDXID")) if pkg.get("SPDXID") else None,
                    identity=identity,
                    name=name,
                    version=version_str,
                    purl=purl_str,
                    supplier=supplier_str,
                    licenses=licenses,
                    checksums=checksums,
                    identity_status=status,
                    raw_extension_data=sanitized_ext,
                )
            )

        return SBOMReport(
            spec_version=spdx_version,
            format_type=MediaType.SPDX_JSON.value,
            inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
            packages=parsed_packages,
            warnings=warnings,
        )

    def _parse_cyclonedx(self, doc: Dict[str, Any]) -> SBOMReport:
        """Parses and normalizes CycloneDX v1.4 / v1.5 JSON document."""
        spec_version = str(doc.get("specVersion", ""))
        if spec_version not in ("1.4", "1.5"):
            raise SBOMParserError(
                f"Unsupported CycloneDX specVersion '{spec_version}'. Supported: 1.4, 1.5",
                error_code="UNSUPPORTED_VERSION",
            )

        components_raw = doc.get("components")
        if not isinstance(components_raw, list):
            raise SBOMParserError(
                "CycloneDX document missing 'components' array",
                error_code="SCHEMA_VALIDATION_FAILED",
            )

        if len(components_raw) > MAX_COMPONENTS_COUNT:
            raise SBOMParserError(
                f"CycloneDX component count ({len(components_raw)}) "
                f"exceeds limit ({MAX_COMPONENTS_COUNT})",
                error_code="RESOURCE_LIMIT_EXCEEDED",
            )

        parsed_packages: List[PackageEvidence] = []
        warnings: List[str] = []
        observed_keys: Dict[str, int] = {}

        for comp in components_raw:
            if not isinstance(comp, dict):
                continue

            name = str(comp.get("name", "")).strip()
            if not name:
                continue

            version = comp.get("version")
            version_str = str(version).strip() if version is not None else None

            publisher = comp.get("publisher") or comp.get("group")
            supplier_str = str(publisher).strip() if publisher else None

            purl_str = str(comp.get("purl")).strip() if comp.get("purl") else None

            # Parse Checksums (hashes)
            checksums: List[ChecksumEvidence] = []
            hashes_raw = comp.get("hashes", [])
            if isinstance(hashes_raw, list):
                for h in hashes_raw:
                    if isinstance(h, dict) and "alg" in h and "content" in h:
                        alg_norm = ChecksumEvidence.normalize_algorithm(str(h["alg"]))
                        digest = str(h["content"]).strip().lower()
                        checksums.append(
                            ChecksumEvidence(normalized_algorithm=alg_norm, digest=digest)
                        )

            checksums = sorted(
                list(set(checksums)), key=lambda c: (c.normalized_algorithm, c.digest)
            )

            # Parse Licenses
            lic_choices: List[str] = []
            lic_raw = comp.get("licenses", [])
            if isinstance(lic_raw, list):
                for l_item in lic_raw:
                    if isinstance(l_item, dict):
                        if "expression" in l_item:
                            lic_choices.append(str(l_item["expression"]))
                        elif "license" in l_item and isinstance(l_item["license"], dict):
                            l_obj = l_item["license"]
                            name_val = l_obj.get("id") or l_obj.get("name")
                            if name_val:
                                lic_choices.append(str(name_val))

            licenses = LicenseEvidence(
                license_declared=lic_choices[0] if lic_choices else None,
                cyclonedx_licenses=lic_choices,
                is_none=len(lic_choices) == 0,
            )

            # Identity Resolution
            identity = None
            if purl_str:
                identity = PackageIdentity.from_purl(purl_str)

            if identity is None:
                identity = PackageIdentity.from_name_supplier(name, supplier_str)

            c_key = identity.canonical_key
            observed_keys[c_key] = observed_keys.get(c_key, 0) + 1
            status = (
                IdentityStatus.UNIQUE if observed_keys[c_key] == 1 else IdentityStatus.DUPLICATE
            )

            ext_data = {
                k: v
                for k, v in comp.items()
                if k
                not in (
                    "name",
                    "version",
                    "publisher",
                    "group",
                    "purl",
                    "hashes",
                    "licenses",
                    "bom-ref",
                )
            }
            sanitized_ext = sanitize_raw_extension_data(ext_data)

            parsed_packages.append(
                PackageEvidence(
                    source_format="CYCLONEDX",
                    source_version=spec_version,
                    source_identifier=str(comp.get("bom-ref")) if comp.get("bom-ref") else None,
                    identity=identity,
                    name=name,
                    version=version_str,
                    purl=purl_str,
                    supplier=supplier_str,
                    licenses=licenses,
                    checksums=checksums,
                    identity_status=status,
                    raw_extension_data=sanitized_ext,
                )
            )

        return SBOMReport(
            spec_version=spec_version,
            format_type=MediaType.CYCLONEDX_JSON.value,
            inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
            packages=parsed_packages,
            warnings=warnings,
        )
