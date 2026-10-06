"""
External Format Representations & Adapters
Structured to represent relevant external SLSA v1.2, in-toto, and DSSE formats;
complete standards validation and cryptographic verification are deferred to later phases.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SLSABuildDefinition(BaseModel):
    buildType: str = Field(..., max_length=256)
    externalParameters: Dict[str, Any] = Field(default_factory=dict)
    internalParameters: Dict[str, Any] = Field(default_factory=dict)
    resolvedDependencies: List[Dict[str, Any]] = Field(default_factory=list)


class SLSARunDetails(BaseModel):
    builder: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    byproducts: List[Dict[str, Any]] = Field(default_factory=list)


class SLSAProvenanceV12(BaseModel):
    """
    External representation of SLSA v1.2 predicate (https://slsa.dev/provenance/v1).
    """

    buildDefinition: SLSABuildDefinition
    runDetails: SLSARunDetails


class InTotoStatement(BaseModel):
    """
    External representation of in-toto attestation statement (in-toto.io/Statement/v0.1 & v1.0).
    """

    type_: str = Field(default="https://in-toto.io/Statement/v0.1", alias="_type")
    subject: List[Dict[str, Any]] = Field(default_factory=list)
    predicateType: str = Field(..., max_length=256)
    predicate: Dict[str, Any] = Field(default_factory=dict)


class DSSESignature(BaseModel):
    keyid: Optional[str] = Field(default=None, max_length=256)
    sig: str = Field(..., max_length=4096)


class DSSEEnvelope(BaseModel):
    """
    External representation of Dead Simple Signing Envelope (DSSE).
    Note: Cryptographic verification is deferred to later phases.
    """

    payload: str = Field(..., max_length=1048576)  # Max 1MB base64/string payload
    payloadType: str = Field(..., max_length=256)
    signatures: List[DSSESignature] = Field(..., min_length=1)
