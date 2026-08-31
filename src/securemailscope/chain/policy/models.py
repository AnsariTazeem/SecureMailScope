"""Versioned policy configuration models (Commit 4).

All models are frozen, extra-forbid, and use constrained fields with existing
enums. These models define the engine-input configuration for deterministic
policy evaluation.
"""

from __future__ import annotations

from decimal import Decimal
from math import isfinite
from typing import Annotated

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from securemailscope.chain.enums import (
    AutomationStatus,
    ConfidenceLevel,
    FindingCategory,
    RecommendationPriority,
    RecommendationScope,
    SeverityLevel,
)
from securemailscope.chain.ids import RECOMMENDATION_PATTERN, SEMVER_PATTERN
from securemailscope.chain.models import StandardsReference
from securemailscope.models import Protocol

# ─────────────────────────────────────────────────────────────────────────────
# Primitive enums
# ─────────────────────────────────────────────────────────────────────────────


class PolicyOperator(str):
    """String enum with exactly: equals, greater_than."""

    @classmethod
    def __get_pydantic_json_schema__(cls, core_schema, handler):
        return handler({"type": "string", "enum": ["equals", "greater_than"]})

    @classmethod
    def __get_pydantic_core_schema__(cls, source, handler):
        from pydantic_core import core_schema as cs

        return cs.with_info_before_validator_function(
            cls._validate, cs.str_schema(), serialization=cs.to_string_ser_schema()
        )

    @classmethod
    def _validate(cls, value: str, _info) -> str:
        if value not in ("equals", "greater_than"):
            raise ValueError(f"unsupported operator: {value!r}")
        return value


class PolicyEvidenceRequirement(str):
    """String enum with exactly: starttls_advertisement, plaintext_command_after_offer."""

    @classmethod
    def __get_pydantic_json_schema__(cls, core_schema, handler):
        return handler(
            {
                "type": "string",
                "enum": ["starttls_advertisement", "plaintext_command_after_offer"],
            }
        )

    @classmethod
    def __get_pydantic_core_schema__(cls, source, handler):
        from pydantic_core import core_schema as cs

        return cs.with_info_before_validator_function(
            cls._validate, cs.str_schema(), serialization=cs.to_string_ser_schema()
        )

    @classmethod
    def _validate(cls, value: str, _info) -> str:
        if value not in ("starttls_advertisement", "plaintext_command_after_offer"):
            raise ValueError(f"unsupported evidence requirement: {value!r}")
        return value


# ─────────────────────────────────────────────────────────────────────────────
# Configuration models
# ─────────────────────────────────────────────────────────────────────────────


class FactRequirement(BaseModel):
    """A single fact requirement for a policy rule.

    Validation rules:
    - equals accepts JSON scalar values only: string, bool, int, finite float, or null
    - greater_than requires an int or finite float; bool rejected as number
    - containers (list, dict) rejected as comparison values
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    fact: Annotated[str, Field(min_length=1, max_length=256)]
    operator: PolicyOperator
    value: object  # validated by model_validator

    @model_validator(mode="after")
    def _validate_value_compatibility(self) -> FactRequirement:
        op = self.operator
        val = self.value

        if op == "equals":
            if not self._is_json_scalar(val):
                raise ValueError("equals operator requires a JSON scalar value")
        elif op == "greater_than":
            if not self._is_finite_number(val):
                raise ValueError(
                    "greater_than operator requires a finite int or float; "
                    "bool and non-numeric values are not allowed"
                )
        return self

    @staticmethod
    def _is_json_scalar(val: object) -> bool:
        if val is None:
            return True
        if isinstance(val, bool):
            return True
        if isinstance(val, int):
            return True
        if isinstance(val, float):
            return isfinite(val)
        if isinstance(val, str):
            return True
        return False

    @staticmethod
    def _is_finite_number(val: object) -> bool:
        if isinstance(val, bool):
            return False
        if isinstance(val, int):
            return True
        if isinstance(val, float):
            return isfinite(val)
        return False


class RecommendationTemplate(BaseModel):
    """A recommendation template referenced by policy rules."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    recommendation_id: Annotated[str, Field(pattern=RECOMMENDATION_PATTERN)]
    title: Annotated[str, Field(min_length=1, max_length=256)]
    summary: Annotated[str, Field(min_length=1, max_length=4096)]
    priority: RecommendationPriority
    action_steps: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=1024)]],
        Field(min_length=1, max_length=32),
    ]
    verification_steps: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=1024)]],
        Field(min_length=1, max_length=32),
    ]
    standards_references: list[StandardsReference]
    scope: RecommendationScope
    automation_status: AutomationStatus

    @field_validator("automation_status")
    @classmethod
    def _enforce_advisory_only(cls, v: AutomationStatus) -> AutomationStatus:
        if v is not AutomationStatus.ADVISORY_ONLY:
            raise ValueError("automation_status must be advisory_only for v1")
        return v


class PolicyRule(BaseModel):
    """A versioned policy rule with typed fact requirements and evidence demands."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: Annotated[str, Field(min_length=1, max_length=128)]
    version: Annotated[str, Field(pattern=SEMVER_PATTERN)]
    title: Annotated[str, Field(min_length=1, max_length=256)]
    category: FindingCategory
    protocols: Annotated[list[Protocol], Field(min_length=1, max_length=16)]
    severity: SeverityLevel
    policy_risk_contribution: Annotated[int, Field(ge=0, le=100)]
    requires: Annotated[list[FactRequirement], Field(min_length=1, max_length=32)]
    evidence_requirements: Annotated[
        list[PolicyEvidenceRequirement], Field(min_length=1, max_length=16)
    ]
    rationale: Annotated[str, Field(min_length=1, max_length=4096)]
    impact: Annotated[str, Field(min_length=1, max_length=4096)]
    recommendation_id: Annotated[str, Field(pattern=RECOMMENDATION_PATTERN)]
    standards_references: list[StandardsReference]

    @model_validator(mode="after")
    def _validate_uniqueness(self) -> PolicyRule:
        # duplicate fact requirements
        seen_facts = set()
        for req in self.requires:
            key = (req.fact, req.operator, req.value)
            if key in seen_facts:
                raise ValueError(f"duplicate fact requirement: {req.fact}")
            seen_facts.add(key)

        # duplicate protocols
        if len(set(self.protocols)) != len(self.protocols):
            raise ValueError("duplicate protocol in rule protocols")

        # duplicate evidence requirements
        if len(set(self.evidence_requirements)) != len(self.evidence_requirements):
            raise ValueError("duplicate evidence requirement")

        return self


class PolicyProfile(BaseModel):
    """A risk profile with confidence adjustment factors and suppression list."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_id: Annotated[str, Field(min_length=1, max_length=64)]
    risk_cap: Annotated[int, Field(ge=0, le=100)]
    confidence_factors: Annotated[
        dict[ConfidenceLevel, Annotated[Decimal, Field(gt=Decimal("0"), le=Decimal("1"))]],
        Field(min_length=4, max_length=4),
    ]
    suppressed_rule_ids: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=128)]],
        Field(default_factory=list, max_length=64),
    ]

    @field_validator("confidence_factors")
    @classmethod
    def _validate_confidence_factors(
        cls, v: dict[ConfidenceLevel, Decimal]
    ) -> dict[ConfidenceLevel, Decimal]:
        required = set(ConfidenceLevel)
        provided = set(v.keys())
        if provided != required:
            missing = required - provided
            extra = provided - required
            msgs = []
            if missing:
                msgs.append(f"missing confidence factors: {sorted(m.value for m in missing)}")
            if extra:
                msgs.append(f"extra confidence factors: {sorted(e.value for e in extra)}")
            raise ValueError("; ".join(msgs))
        for level, factor in v.items():
            if not (Decimal("0") < factor <= Decimal("1")):
                raise ValueError(
                    f"confidence factor for {level.value} must be >0 and <=1, got {factor}"
                )
        return v

    @field_validator("suppressed_rule_ids")
    @classmethod
    def _validate_suppressed_unique(cls, v: list[str]) -> list[str]:
        if len(set(v)) != len(v):
            raise ValueError("duplicate suppressed rule IDs")
        return v


class PolicyPack(BaseModel):
    """Complete versioned policy pack with profiles, rules, and recommendations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pack_id: Annotated[str, Field(min_length=1, max_length=64)]
    version: Annotated[str, Field(pattern=SEMVER_PATTERN)]
    profiles: Annotated[list[PolicyProfile], Field(min_length=1, max_length=16)]
    rules: Annotated[list[PolicyRule], Field(min_length=1, max_length=128)]
    recommendations: Annotated[list[RecommendationTemplate], Field(min_length=1, max_length=128)]

    @model_validator(mode="after")
    def _validate_cross_references(self) -> PolicyPack:
        # unique profile IDs
        profile_ids = [p.profile_id for p in self.profiles]
        if len(set(profile_ids)) != len(profile_ids):
            raise ValueError("duplicate profile_id")

        # unique (rule_id, version) identities
        rule_identities = [(r.rule_id, r.version) for r in self.rules]
        if len(set(rule_identities)) != len(rule_identities):
            raise ValueError("duplicate (rule_id, version) identity")

        # for this pack, no duplicate rule_id even with another version
        rule_ids = [r.rule_id for r in self.rules]
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("duplicate rule_id in pack (version not allowed to differ)")

        # unique recommendation IDs
        rec_ids = [r.recommendation_id for r in self.recommendations]
        if len(set(rec_ids)) != len(rec_ids):
            raise ValueError("duplicate recommendation_id")

        # every rule recommendation_id resolves
        rec_id_set = set(rec_ids)
        for rule in self.rules:
            if rule.recommendation_id not in rec_id_set:
                raise ValueError(
                    f"rule {rule.rule_id} references unknown recommendation "
                    f"{rule.recommendation_id}"
                )

        # every suppressed rule ID resolves
        rule_id_set = set(rule_ids)
        for profile in self.profiles:
            for suppressed in profile.suppressed_rule_ids:
                if suppressed not in rule_id_set:
                    raise ValueError(
                        f"profile {profile.profile_id} suppresses unknown rule {suppressed}"
                    )

        # no orphan recommendation template
        referenced_rec_ids = {r.recommendation_id for r in self.rules}
        for rec_id in rec_ids:
            if rec_id not in referenced_rec_ids:
                raise ValueError(f"orphan recommendation template: {rec_id}")

        return self


class PolicyEvaluationContext(BaseModel):
    """Explicit evaluation context; engine must never call datetime.now()."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_id: Annotated[str, Field(min_length=1, max_length=64)]
    evaluated_at: AwareDatetime
    base_configuration_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


# ─────────────────────────────────────────────────────────────────────────────
# Bounded constants
# ─────────────────────────────────────────────────────────────────────────────

MAX_YAML_BYTES = 65_536
MAX_NESTING_DEPTH = 20
MAX_PARSED_NODES = 2_048
MAX_STRING_LENGTH = 4_096
