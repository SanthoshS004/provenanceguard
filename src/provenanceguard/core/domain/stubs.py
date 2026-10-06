"""
Declarative Domain Stubs for Policy & Risk Specifications
"""

from typing import Dict, List

from pydantic import BaseModel, Field


class RiskRule(BaseModel):
    id: str = Field(..., max_length=256)
    category: str = Field(..., max_length=100)
    weight: int = Field(..., ge=0, le=100)
    explanation: str = Field(..., max_length=1024)


class Risk(BaseModel):
    """
    Declarative domain stub for risk specification.
    Note: Risk scoring algorithms are deferred to later phases.
    """

    id: str = Field(..., max_length=256)
    name: str = Field(..., max_length=256)
    rules: List[RiskRule] = Field(default_factory=list)


class PolicyRule(BaseModel):
    id: str = Field(..., max_length=256)
    rule_type: str = Field(..., max_length=100)
    parameters: Dict[str, str] = Field(default_factory=dict)


class Policy(BaseModel):
    """
    Declarative domain stub for security policy specification.
    Note: Policy engine evaluation is deferred to later phases.
    """

    id: str = Field(..., max_length=256)
    project_id: str = Field(..., max_length=256)
    name: str = Field(..., max_length=256)
    warning_threshold: int = Field(default=30, ge=0, le=100)
    block_threshold: int = Field(default=70, ge=0, le=100)
    rules: List[PolicyRule] = Field(default_factory=list)
    fail_on_new_functions: bool = True
    fail_on_unexpected_imports: bool = True
