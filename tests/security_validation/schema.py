"""
Pydantic Schemas for Security Validation Attack Scenarios & Negative Controls.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from provenanceguard.core.domain.enums import FindingCategory


class ScenarioMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    scenario_id: str = Field(..., max_length=100)
    name: str = Field(..., max_length=256)
    description: str = Field(..., max_length=1024)
    threat_actor: str = Field(..., max_length=256)
    category: str = Field(..., max_length=100)


class ExpectedResults(BaseModel):
    model_config = ConfigDict(frozen=True)

    expected_decision: Optional[str] = Field(None)  # PASS, PASS_WITH_WARNING, BLOCK, N/A
    expected_finding_category: Optional[FindingCategory] = Field(None)
    expected_risk_score: Optional[int] = Field(None, ge=0, le=100)
    expected_triggered_rules: List[str] = Field(default_factory=list)
    expected_exit_code: int = Field(0)
    expected_audit_event: Optional[str] = Field(None)


class ScenarioSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    metadata: ScenarioMetadata
    is_negative_control: bool = Field(default=False)
    policy_config: Dict[str, Any] = Field(default_factory=dict)
    expected_results: ExpectedResults
