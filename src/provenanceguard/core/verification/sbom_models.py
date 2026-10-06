"""
Strongly Typed Domain Models for SPDX & CycloneDX SBOM Evidence and Package Inventory Comparison.
"""

from enum import Enum
from typing import Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, JsonValue


class SBOMInventoryCompleteness(str, Enum):
    """Represents the inventory completeness state of an SBOM document."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class IdentityStatus(str, Enum):
    """Represents the resolution status of a package identity."""

    UNIQUE = "UNIQUE"
    DUPLICATE = "DUPLICATE"
    AMBIGUOUS = "AMBIGUOUS"
    UNRESOLVED = "UNRESOLVED"


class PackageIdentity(BaseModel):
    """
    Version-free canonical package identity representation.
    EXCLUDES the version string so version shifts resolve to the same package identity.
    """

    model_config = ConfigDict(frozen=True)

    type: Optional[str] = None  # e.g., 'pypi', 'npm', 'maven'
    namespace: Optional[str] = None
    name: str
    qualifiers: Dict[str, str] = Field(default_factory=dict)
    subpath: Optional[str] = None
    supplier: Optional[str] = None
    canonical_key: str

    @classmethod
    def from_purl(cls, purl_str: str) -> Optional["PackageIdentity"]:
        """
        Parses a Package URL string according to the Package URL specification,
        retaining identity components while strictly EXCLUDING the version field.
        """
        if not purl_str or not purl_str.startswith("pkg:"):
            return None

        try:
            # Scheme check
            remainder = purl_str[4:]
            if "/" not in remainder:
                return None

            pkg_type, rest = remainder.split("/", 1)
            pkg_type = pkg_type.lower()

            # Separate subpath (#)
            subpath = None
            if "#" in rest:
                rest, subpath = rest.split("#", 1)

            # Separate qualifiers (?)
            qualifiers: Dict[str, str] = {}
            if "?" in rest:
                rest, qual_str = rest.split("?", 1)
                for pair in qual_str.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        qualifiers[k.lower()] = v

            # Separate version (@)
            if "@" in rest:
                name_part, _version_part = rest.split("@", 1)
            else:
                name_part = rest

            # Separate namespace and name
            if "/" in name_part:
                namespace_part, name = name_part.rsplit("/", 1)
                namespace = namespace_part if namespace_part else None
            else:
                namespace = None
                name = name_part

            if not name:
                return None

            # Construct canonical key without version
            qual_canonical = (
                "?" + "&".join(f"{k}={qualifiers[k]}" for k in sorted(qualifiers.keys()))
                if qualifiers
                else ""
            )
            subpath_canonical = f"#{subpath}" if subpath else ""
            ns_canonical = f"{namespace}/" if namespace else ""
            canonical_key = (
                f"pkg:{pkg_type}/{ns_canonical}{name}{qual_canonical}{subpath_canonical}"
            )

            return cls(
                type=pkg_type,
                namespace=namespace,
                name=name,
                qualifiers=qualifiers,
                subpath=subpath,
                canonical_key=canonical_key,
            )
        except Exception:
            return None

    @classmethod
    def from_name_supplier(cls, name: str, supplier: Optional[str] = None) -> "PackageIdentity":
        """
        Constructs a fallback PackageIdentity from name + supplier (version-free).
        Name-only fallback is NOT used if name is ambiguous.
        """
        clean_name = name.strip().lower()
        clean_supplier = supplier.strip().lower() if supplier else ""

        if clean_supplier:
            key = f"fallback:{clean_supplier}/{clean_name}"
        else:
            key = f"name:{clean_name}"

        return cls(
            name=name,
            supplier=supplier,
            canonical_key=key,
        )


class ChecksumEvidence(BaseModel):
    """
    Checksum evidence for a package, keyed by normalized algorithm and digest.
    """

    model_config = ConfigDict(frozen=True)

    normalized_algorithm: str  # e.g., 'SHA256', 'SHA1', 'MD5', 'SHA512'
    digest: str

    @classmethod
    def normalize_algorithm(cls, alg: str) -> str:
        """Deterministically normalizes checksum algorithm names."""
        clean = alg.strip().upper().replace("-", "").replace("_", "")
        if clean in ("SHA256", "SHA2"):
            return "SHA256"
        if clean == "SHA512":
            return "SHA512"
        if clean in ("SHA1", "SHA"):
            return "SHA1"
        if clean == "MD5":
            return "MD5"
        return clean


class LicenseEvidence(BaseModel):
    """
    Structured representation preserving SPDX and CycloneDX license details.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    license_declared: Optional[str] = None  # SPDX licenseDeclared or CycloneDX expression/name
    license_concluded: Optional[str] = None  # SPDX licenseConcluded
    license_info_from_files: List[str] = Field(default_factory=list)  # SPDX licenseInfoFromFiles
    cyclonedx_licenses: List[str] = Field(default_factory=list)  # CycloneDX license choices
    is_none: bool = False  # Special value: NONE
    is_noassertion: bool = False  # Special value: NOASSERTION

    def canonical_string(self) -> str:
        """Returns a deterministic syntactic string representation for comparison."""
        if self.is_none:
            return "NONE"
        if self.is_noassertion:
            return "NOASSERTION"
        if self.license_declared:
            return self.license_declared.strip()
        if self.license_concluded:
            return self.license_concluded.strip()
        if self.cyclonedx_licenses:
            return "|".join(sorted(self.cyclonedx_licenses))
        if self.license_info_from_files:
            return "|".join(sorted(self.license_info_from_files))
        return "NOASSERTION"


class PackageEvidence(BaseModel):
    """
    Canonical normalized package inventory item extracted from SPDX or CycloneDX.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    source_format: str  # 'SPDX' or 'CYCLONEDX'
    source_version: str  # 'SPDX-2.2', 'SPDX-2.3', '1.4', '1.5'
    source_identifier: Optional[str] = None  # SPDXID or bom-ref
    identity: PackageIdentity
    name: str
    version: Optional[str] = None  # Separately comparable version attribute
    purl: Optional[str] = None
    supplier: Optional[str] = None
    licenses: LicenseEvidence = Field(default_factory=LicenseEvidence)
    checksums: List[ChecksumEvidence] = Field(default_factory=list)
    identity_status: IdentityStatus = IdentityStatus.UNIQUE
    raw_extension_data: Dict[str, JsonValue] = Field(default_factory=dict)


class SBOMReport(BaseModel):
    """
    Normalized package inventory report extracted from an SBOM document.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    spec_version: str  # 'SPDX-2.2', 'SPDX-2.3', '1.4', '1.5'
    format_type: str  # 'SPDX_JSON' or 'CYCLONEDX_JSON'
    inventory_completeness: SBOMInventoryCompleteness = SBOMInventoryCompleteness.UNKNOWN
    packages: List[PackageEvidence] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class PackageDeltaType(str, Enum):
    """Classifies package inventory modifications."""

    ADDED_PACKAGE = "ADDED_PACKAGE"
    REMOVED_PACKAGE = "REMOVED_PACKAGE"
    VERSION_CHANGED = "VERSION_CHANGED"
    LICENSE_CHANGED = "LICENSE_CHANGED"
    CHECKSUM_MISMATCH = "CHECKSUM_MISMATCH"


class PackageDelta(BaseModel):
    """
    Represents an objective modification between reference and target package inventories.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    delta_type: PackageDeltaType
    package_name: str
    purl: Optional[str] = None
    details: str
    old_value: Optional[Union[str, JsonValue]] = None
    new_value: Optional[Union[str, JsonValue]] = None


class SBOMComparisonResult(BaseModel):
    """
    Deterministic result payload for SBOM package inventory evidence comparison.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    reference_sbom_digest: str
    target_sbom_digest: str
    reference_completeness: SBOMInventoryCompleteness
    target_completeness: SBOMInventoryCompleteness
    package_deltas: List[PackageDelta] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

    def sort_deltas(self) -> "SBOMComparisonResult":
        """Sorts all package deltas deterministically."""
        self.package_deltas.sort(
            key=lambda d: (
                d.delta_type.value,
                d.package_name,
                str(d.purl or ""),
                str(d.old_value or ""),
                str(d.new_value or ""),
            )
        )
        self.warnings.sort()
        return self
