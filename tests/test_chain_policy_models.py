"""Tests for policy configuration models (Commit 4)."""

from __future__ import annotations

from decimal import Decimal

import pytest
from pydantic import ValidationError

from securemailscope.chain.enums import (
    AutomationStatus,
    ConfidenceLevel,
    FindingCategory,
    RecommendationPriority,
    RecommendationScope,
    SeverityLevel,
)
from securemailscope.chain.models import StandardsReference
from securemailscope.chain.policy.models import (
    FactRequirement,
    PolicyPack,
    PolicyProfile,
    PolicyRule,
    RecommendationTemplate,
)
from securemailscope.models import Protocol


class TestPolicyOperator:
    def test_valid_operators(self):
        assert FactRequirement(fact="x", operator="equals", value=True).operator == "equals"
        assert (
            FactRequirement(fact="x", operator="greater_than", value=5).operator == "greater_than"
        )

    def test_invalid_operator_rejected(self):
        with pytest.raises(ValidationError):
            FactRequirement(fact="x", operator="contains", value="foo")


class TestPolicyEvidenceRequirement:
    def test_valid_requirements(self):
        req = FactRequirement(
            fact="x",
            operator="equals",
            value=True,
        )
        assert req.value is True
        # Evidence requirement is validated through PolicyRule


class TestFactRequirement:
    def test_equals_accepts_json_scalars(self):
        for val in [None, True, False, 42, 3.14, "hello"]:
            req = FactRequirement(fact="x", operator="equals", value=val)
            assert req.value == val

    def test_equals_rejects_containers(self):
        for val in [[], {}, [1], {"a": 1}]:
            with pytest.raises(ValidationError):
                FactRequirement(fact="x", operator="equals", value=val)

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_equals_rejects_non_finite_numbers(self, value):
        with pytest.raises(ValidationError):
            FactRequirement(fact="x", operator="equals", value=value)

    def test_greater_than_accepts_numbers(self):
        for val in [0, 1, -5, 3.14, -2.5]:
            req = FactRequirement(fact="x", operator="greater_than", value=val)
            assert req.value == val

    def test_greater_than_rejects_bool(self):
        with pytest.raises(ValidationError):
            FactRequirement(fact="x", operator="greater_than", value=True)
        with pytest.raises(ValidationError):
            FactRequirement(fact="x", operator="greater_than", value=False)

    def test_greater_than_rejects_non_numbers(self):
        for val in [None, "hello", [], {}]:
            with pytest.raises(ValidationError):
                FactRequirement(fact="x", operator="greater_than", value=val)

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_greater_than_rejects_non_finite_numbers(self, value):
        with pytest.raises(ValidationError):
            FactRequirement(fact="x", operator="greater_than", value=value)


class TestRecommendationTemplate:
    def test_valid_template(self):
        tmpl = RecommendationTemplate(
            recommendation_id="REC-TEST-001",
            title="Test",
            summary="Summary",
            priority=RecommendationPriority.HIGH,
            action_steps=["Step 1"],
            verification_steps=["Verify 1"],
            standards_references=[StandardsReference(id="RFC1234")],
            scope=RecommendationScope.SERVICE,
            automation_status=AutomationStatus.ADVISORY_ONLY,
        )
        assert tmpl.automation_status == AutomationStatus.ADVISORY_ONLY

    def test_non_advisory_rejected(self):
        with pytest.raises(ValidationError):
            RecommendationTemplate(
                recommendation_id="REC-TEST-001",
                title="Test",
                summary="Summary",
                priority=RecommendationPriority.HIGH,
                action_steps=["Step 1"],
                verification_steps=["Verify 1"],
                standards_references=[],
                scope=RecommendationScope.SERVICE,
                automation_status="automated",
            )

    def test_empty_lists_rejected(self):
        with pytest.raises(ValidationError):
            RecommendationTemplate(
                recommendation_id="REC-TEST-001",
                title="Test",
                summary="Summary",
                priority=RecommendationPriority.HIGH,
                action_steps=[],
                verification_steps=["Verify 1"],
                standards_references=[],
                scope=RecommendationScope.SERVICE,
                automation_status=AutomationStatus.ADVISORY_ONLY,
            )


class TestPolicyRule:
    def test_valid_rule(self):
        rule = PolicyRule(
            rule_id="TEST-001",
            version="1.0.0",
            title="Test Rule",
            category=FindingCategory.ENCRYPTION_TRANSITION,
            protocols=[Protocol.SMTP],
            severity=SeverityLevel.HIGH,
            policy_risk_contribution=25,
            requires=[FactRequirement(fact="starttls_advertised", operator="equals", value=True)],
            evidence_requirements=["starttls_advertisement"],
            rationale="Test rationale",
            impact="Test impact",
            recommendation_id="REC-TEST-001",
            standards_references=[StandardsReference(id="RFC1234")],
        )
        assert rule.rule_id == "TEST-001"

    def test_duplicate_fact_requirements_rejected(self):
        with pytest.raises(ValidationError):
            PolicyRule(
                rule_id="TEST-001",
                version="1.0.0",
                title="Test",
                category=FindingCategory.ENCRYPTION_TRANSITION,
                protocols=[Protocol.SMTP],
                severity=SeverityLevel.HIGH,
                policy_risk_contribution=25,
                requires=[
                    FactRequirement(fact="x", operator="equals", value=True),
                    FactRequirement(fact="x", operator="equals", value=True),
                ],
                evidence_requirements=["starttls_advertisement"],
                rationale="Test",
                impact="Test",
                recommendation_id="REC-TEST-001",
                standards_references=[],
            )

    def test_duplicate_protocols_rejected(self):
        with pytest.raises(ValidationError):
            PolicyRule(
                rule_id="TEST-001",
                version="1.0.0",
                title="Test",
                category=FindingCategory.ENCRYPTION_TRANSITION,
                protocols=[Protocol.SMTP, Protocol.SMTP],
                severity=SeverityLevel.HIGH,
                policy_risk_contribution=25,
                requires=[FactRequirement(fact="x", operator="equals", value=True)],
                evidence_requirements=["starttls_advertisement"],
                rationale="Test",
                impact="Test",
                recommendation_id="REC-TEST-001",
                standards_references=[],
            )

    def test_duplicate_evidence_requirements_rejected(self):
        with pytest.raises(ValidationError):
            PolicyRule(
                rule_id="TEST-001",
                version="1.0.0",
                title="Test",
                category=FindingCategory.ENCRYPTION_TRANSITION,
                protocols=[Protocol.SMTP],
                severity=SeverityLevel.HIGH,
                policy_risk_contribution=25,
                requires=[FactRequirement(fact="x", operator="equals", value=True)],
                evidence_requirements=["starttls_advertisement", "starttls_advertisement"],
                rationale="Test",
                impact="Test",
                recommendation_id="REC-TEST-001",
                standards_references=[],
            )

    def test_invalid_operator_rejected(self):
        with pytest.raises(ValidationError):
            PolicyRule(
                rule_id="TEST-001",
                version="1.0.0",
                title="Test",
                category=FindingCategory.ENCRYPTION_TRANSITION,
                protocols=[Protocol.SMTP],
                severity=SeverityLevel.HIGH,
                policy_risk_contribution=25,
                requires=[FactRequirement(fact="x", operator="contains", value="foo")],
                evidence_requirements=["starttls_advertisement"],
                rationale="Test",
                impact="Test",
                recommendation_id="REC-TEST-001",
                standards_references=[],
            )


class TestPolicyProfile:
    def test_valid_profile(self):
        profile = PolicyProfile(
            profile_id="test-profile",
            risk_cap=100,
            confidence_factors={
                ConfidenceLevel.HIGH: Decimal("1.00"),
                ConfidenceLevel.MEDIUM: Decimal("0.75"),
                ConfidenceLevel.LOW: Decimal("0.50"),
                ConfidenceLevel.NOT_SCORED: Decimal("0.25"),
            },
            suppressed_rule_ids=[],
        )
        assert profile.profile_id == "test-profile"

    def test_missing_confidence_factor_rejected(self):
        with pytest.raises(ValidationError):
            PolicyProfile(
                profile_id="test",
                risk_cap=100,
                confidence_factors={
                    ConfidenceLevel.HIGH: Decimal("1.00"),
                    ConfidenceLevel.MEDIUM: Decimal("0.75"),
                    # LOW missing
                    ConfidenceLevel.NOT_SCORED: Decimal("0.25"),
                },
                suppressed_rule_ids=[],
            )

    def test_extra_confidence_factor_rejected(self):
        with pytest.raises(ValidationError):
            PolicyProfile(
                profile_id="test",
                risk_cap=100,
                confidence_factors={
                    ConfidenceLevel.HIGH: Decimal("1.00"),
                    ConfidenceLevel.MEDIUM: Decimal("0.75"),
                    ConfidenceLevel.LOW: Decimal("0.50"),
                    ConfidenceLevel.NOT_SCORED: Decimal("0.25"),
                    "extra": Decimal("0.10"),
                },
                suppressed_rule_ids=[],
            )

    def test_factor_bounds_enforced(self):
        with pytest.raises(ValidationError):
            PolicyProfile(
                profile_id="test",
                risk_cap=100,
                confidence_factors={
                    ConfidenceLevel.HIGH: Decimal("1.01"),
                    ConfidenceLevel.MEDIUM: Decimal("0.75"),
                    ConfidenceLevel.LOW: Decimal("0.50"),
                    ConfidenceLevel.NOT_SCORED: Decimal("0.25"),
                },
                suppressed_rule_ids=[],
            )
        with pytest.raises(ValidationError):
            PolicyProfile(
                profile_id="test",
                risk_cap=100,
                confidence_factors={
                    ConfidenceLevel.HIGH: Decimal("0"),
                    ConfidenceLevel.MEDIUM: Decimal("0.75"),
                    ConfidenceLevel.LOW: Decimal("0.50"),
                    ConfidenceLevel.NOT_SCORED: Decimal("0.25"),
                },
                suppressed_rule_ids=[],
            )

    def test_duplicate_suppressed_rejected(self):
        with pytest.raises(ValidationError):
            PolicyProfile(
                profile_id="test",
                risk_cap=100,
                confidence_factors={
                    ConfidenceLevel.HIGH: Decimal("1.00"),
                    ConfidenceLevel.MEDIUM: Decimal("0.75"),
                    ConfidenceLevel.LOW: Decimal("0.50"),
                    ConfidenceLevel.NOT_SCORED: Decimal("0.25"),
                },
                suppressed_rule_ids=["RULE-001", "RULE-001"],
            )


class TestPolicyPack:
    def test_minimal_valid_pack(self):
        pack = PolicyPack(
            pack_id="TEST-PACK",
            version="1.0.0",
            profiles=[
                PolicyProfile(
                    profile_id="default",
                    risk_cap=100,
                    confidence_factors={
                        ConfidenceLevel.HIGH: Decimal("1.00"),
                        ConfidenceLevel.MEDIUM: Decimal("0.75"),
                        ConfidenceLevel.LOW: Decimal("0.50"),
                        ConfidenceLevel.NOT_SCORED: Decimal("0.25"),
                    },
                    suppressed_rule_ids=[],
                )
            ],
            rules=[
                PolicyRule(
                    rule_id="TEST-001",
                    version="1.0.0",
                    title="Test",
                    category=FindingCategory.ENCRYPTION_TRANSITION,
                    protocols=[Protocol.SMTP],
                    severity=SeverityLevel.HIGH,
                    policy_risk_contribution=25,
                    requires=[FactRequirement(fact="x", operator="equals", value=True)],
                    evidence_requirements=["starttls_advertisement"],
                    rationale="Test",
                    impact="Test",
                    recommendation_id="REC-TEST-001",
                    standards_references=[StandardsReference(id="RFC1234")],
                )
            ],
            recommendations=[
                RecommendationTemplate(
                    recommendation_id="REC-TEST-001",
                    title="Test",
                    summary="Test",
                    priority=RecommendationPriority.HIGH,
                    action_steps=["Step 1"],
                    verification_steps=["Verify 1"],
                    standards_references=[StandardsReference(id="RFC1234")],
                    scope=RecommendationScope.SERVICE,
                    automation_status=AutomationStatus.ADVISORY_ONLY,
                )
            ],
        )
        assert pack.pack_id == "TEST-PACK"

    def test_duplicate_profile_ids_rejected(self):
        with pytest.raises(ValidationError):
            PolicyPack(
                pack_id="TEST",
                version="1.0.0",
                profiles=[
                    PolicyProfile(
                        profile_id="dup",
                        risk_cap=100,
                        confidence_factors={
                            ConfidenceLevel.HIGH: Decimal("1.00"),
                            ConfidenceLevel.MEDIUM: Decimal("0.75"),
                            ConfidenceLevel.LOW: Decimal("0.50"),
                            ConfidenceLevel.NOT_SCORED: Decimal("0.25"),
                        },
                        suppressed_rule_ids=[],
                    ),
                    PolicyProfile(
                        profile_id="dup",
                        risk_cap=100,
                        confidence_factors={
                            ConfidenceLevel.HIGH: Decimal("1.00"),
                            ConfidenceLevel.MEDIUM: Decimal("0.75"),
                            ConfidenceLevel.LOW: Decimal("0.50"),
                            ConfidenceLevel.NOT_SCORED: Decimal("0.25"),
                        },
                        suppressed_rule_ids=[],
                    ),
                ],
                rules=[],
                recommendations=[],
            )

    def test_duplicate_rule_identity_rejected(self):
        with pytest.raises(ValidationError):
            PolicyPack(
                pack_id="TEST",
                version="1.0.0",
                profiles=[
                    PolicyProfile(
                        profile_id="default",
                        risk_cap=100,
                        confidence_factors={
                            ConfidenceLevel.HIGH: Decimal("1.00"),
                            ConfidenceLevel.MEDIUM: Decimal("0.75"),
                            ConfidenceLevel.LOW: Decimal("0.50"),
                            ConfidenceLevel.NOT_SCORED: Decimal("0.25"),
                        },
                        suppressed_rule_ids=[],
                    )
                ],
                rules=[
                    PolicyRule(
                        rule_id="RULE-001",
                        version="1.0.0",
                        title="Test",
                        category=FindingCategory.ENCRYPTION_TRANSITION,
                        protocols=[Protocol.SMTP],
                        severity=SeverityLevel.HIGH,
                        policy_risk_contribution=25,
                        requires=[FactRequirement(fact="x", operator="equals", value=True)],
                        evidence_requirements=["starttls_advertisement"],
                        rationale="Test",
                        impact="Test",
                        recommendation_id="REC-001",
                        standards_references=[StandardsReference(id="RFC1234")],
                    ),
                    PolicyRule(
                        rule_id="RULE-001",
                        version="1.0.1",
                        title="Test v2",
                        category=FindingCategory.ENCRYPTION_TRANSITION,
                        protocols=[Protocol.SMTP],
                        severity=SeverityLevel.HIGH,
                        policy_risk_contribution=25,
                        requires=[FactRequirement(fact="x", operator="equals", value=True)],
                        evidence_requirements=["starttls_advertisement"],
                        rationale="Test",
                        impact="Test",
                        recommendation_id="REC-001",
                        standards_references=[StandardsReference(id="RFC1234")],
                    ),
                ],
                recommendations=[
                    RecommendationTemplate(
                        recommendation_id="REC-001",
                        title="Test",
                        summary="Test",
                        priority=RecommendationPriority.HIGH,
                        action_steps=["Step 1"],
                        verification_steps=["Verify 1"],
                        standards_references=[StandardsReference(id="RFC1234")],
                        scope=RecommendationScope.SERVICE,
                        automation_status=AutomationStatus.ADVISORY_ONLY,
                    )
                ],
            )

    def test_duplicate_rule_id_same_version_rejected(self):
        with pytest.raises(ValidationError):
            PolicyPack(
                pack_id="TEST",
                version="1.0.0",
                profiles=[
                    PolicyProfile(
                        profile_id="default",
                        risk_cap=100,
                        confidence_factors={
                            ConfidenceLevel.HIGH: Decimal("1.00"),
                            ConfidenceLevel.MEDIUM: Decimal("0.75"),
                            ConfidenceLevel.LOW: Decimal("0.50"),
                            ConfidenceLevel.NOT_SCORED: Decimal("0.25"),
                        },
                        suppressed_rule_ids=[],
                    )
                ],
                rules=[
                    PolicyRule(
                        rule_id="RULE-001",
                        version="1.0.0",
                        title="Test",
                        category=FindingCategory.ENCRYPTION_TRANSITION,
                        protocols=[Protocol.SMTP],
                        severity=SeverityLevel.HIGH,
                        policy_risk_contribution=25,
                        requires=[FactRequirement(fact="x", operator="equals", value=True)],
                        evidence_requirements=["starttls_advertisement"],
                        rationale="Test",
                        impact="Test",
                        recommendation_id="REC-001",
                        standards_references=[StandardsReference(id="RFC1234")],
                    ),
                    PolicyRule(
                        rule_id="RULE-001",
                        version="1.0.0",
                        title="Test 2",
                        category=FindingCategory.ENCRYPTION_TRANSITION,
                        protocols=[Protocol.SMTP],
                        severity=SeverityLevel.HIGH,
                        policy_risk_contribution=25,
                        requires=[FactRequirement(fact="x", operator="equals", value=True)],
                        evidence_requirements=["starttls_advertisement"],
                        rationale="Test",
                        impact="Test",
                        recommendation_id="REC-001",
                        standards_references=[StandardsReference(id="RFC1234")],
                    ),
                ],
                recommendations=[
                    RecommendationTemplate(
                        recommendation_id="REC-001",
                        title="Test",
                        summary="Test",
                        priority=RecommendationPriority.HIGH,
                        action_steps=["Step 1"],
                        verification_steps=["Verify 1"],
                        standards_references=[StandardsReference(id="RFC1234")],
                        scope=RecommendationScope.SERVICE,
                        automation_status=AutomationStatus.ADVISORY_ONLY,
                    )
                ],
            )

    def test_duplicate_recommendation_ids_rejected(self):
        with pytest.raises(ValidationError):
            PolicyPack(
                pack_id="TEST",
                version="1.0.0",
                profiles=[
                    PolicyProfile(
                        profile_id="default",
                        risk_cap=100,
                        confidence_factors={
                            ConfidenceLevel.HIGH: Decimal("1.00"),
                            ConfidenceLevel.MEDIUM: Decimal("0.75"),
                            ConfidenceLevel.LOW: Decimal("0.50"),
                            ConfidenceLevel.NOT_SCORED: Decimal("0.25"),
                        },
                        suppressed_rule_ids=[],
                    )
                ],
                rules=[
                    PolicyRule(
                        rule_id="RULE-001",
                        version="1.0.0",
                        title="Test",
                        category=FindingCategory.ENCRYPTION_TRANSITION,
                        protocols=[Protocol.SMTP],
                        severity=SeverityLevel.HIGH,
                        policy_risk_contribution=25,
                        requires=[FactRequirement(fact="x", operator="equals", value=True)],
                        evidence_requirements=["starttls_advertisement"],
                        rationale="Test",
                        impact="Test",
                        recommendation_id="REC-001",
                        standards_references=[StandardsReference(id="RFC1234")],
                    )
                ],
                recommendations=[
                    RecommendationTemplate(
                        recommendation_id="REC-001",
                        title="Test",
                        summary="Test",
                        priority=RecommendationPriority.HIGH,
                        action_steps=["Step 1"],
                        verification_steps=["Verify 1"],
                        standards_references=[StandardsReference(id="RFC1234")],
                        scope=RecommendationScope.SERVICE,
                        automation_status=AutomationStatus.ADVISORY_ONLY,
                    ),
                    RecommendationTemplate(
                        recommendation_id="REC-001",
                        title="Test 2",
                        summary="Test 2",
                        priority=RecommendationPriority.HIGH,
                        action_steps=["Step 1"],
                        verification_steps=["Verify 1"],
                        standards_references=[StandardsReference(id="RFC1234")],
                        scope=RecommendationScope.SERVICE,
                        automation_status=AutomationStatus.ADVISORY_ONLY,
                    ),
                ],
            )

    def test_unresolved_recommendation_rejected(self):
        with pytest.raises(ValidationError):
            PolicyPack(
                pack_id="TEST",
                version="1.0.0",
                profiles=[
                    PolicyProfile(
                        profile_id="default",
                        risk_cap=100,
                        confidence_factors={
                            ConfidenceLevel.HIGH: Decimal("1.00"),
                            ConfidenceLevel.MEDIUM: Decimal("0.75"),
                            ConfidenceLevel.LOW: Decimal("0.50"),
                            ConfidenceLevel.NOT_SCORED: Decimal("0.25"),
                        },
                        suppressed_rule_ids=[],
                    )
                ],
                rules=[
                    PolicyRule(
                        rule_id="RULE-001",
                        version="1.0.0",
                        title="Test",
                        category=FindingCategory.ENCRYPTION_TRANSITION,
                        protocols=[Protocol.SMTP],
                        severity=SeverityLevel.HIGH,
                        policy_risk_contribution=25,
                        requires=[FactRequirement(fact="x", operator="equals", value=True)],
                        evidence_requirements=["starttls_advertisement"],
                        rationale="Test",
                        impact="Test",
                        recommendation_id="REC-MISSING",
                        standards_references=[StandardsReference(id="RFC1234")],
                    )
                ],
                recommendations=[
                    RecommendationTemplate(
                        recommendation_id="REC-001",
                        title="Test",
                        summary="Test",
                        priority=RecommendationPriority.HIGH,
                        action_steps=["Step 1"],
                        verification_steps=["Verify 1"],
                        standards_references=[StandardsReference(id="RFC1234")],
                        scope=RecommendationScope.SERVICE,
                        automation_status=AutomationStatus.ADVISORY_ONLY,
                    )
                ],
            )

    def test_unresolved_suppressed_rule_rejected(self):
        with pytest.raises(ValidationError):
            PolicyPack(
                pack_id="TEST",
                version="1.0.0",
                profiles=[
                    PolicyProfile(
                        profile_id="default",
                        risk_cap=100,
                        confidence_factors={
                            ConfidenceLevel.HIGH: Decimal("1.00"),
                            ConfidenceLevel.MEDIUM: Decimal("0.75"),
                            ConfidenceLevel.LOW: Decimal("0.50"),
                            ConfidenceLevel.NOT_SCORED: Decimal("0.25"),
                        },
                        suppressed_rule_ids=["NONEXISTENT-RULE"],
                    )
                ],
                rules=[
                    PolicyRule(
                        rule_id="RULE-001",
                        version="1.0.0",
                        title="Test",
                        category=FindingCategory.ENCRYPTION_TRANSITION,
                        protocols=[Protocol.SMTP],
                        severity=SeverityLevel.HIGH,
                        policy_risk_contribution=25,
                        requires=[FactRequirement(fact="x", operator="equals", value=True)],
                        evidence_requirements=["starttls_advertisement"],
                        rationale="Test",
                        impact="Test",
                        recommendation_id="REC-001",
                        standards_references=[StandardsReference(id="RFC1234")],
                    )
                ],
                recommendations=[
                    RecommendationTemplate(
                        recommendation_id="REC-001",
                        title="Test",
                        summary="Test",
                        priority=RecommendationPriority.HIGH,
                        action_steps=["Step 1"],
                        verification_steps=["Verify 1"],
                        standards_references=[StandardsReference(id="RFC1234")],
                        scope=RecommendationScope.SERVICE,
                        automation_status=AutomationStatus.ADVISORY_ONLY,
                    )
                ],
            )

    def test_orphan_recommendation_rejected(self):
        with pytest.raises(ValidationError):
            PolicyPack(
                pack_id="TEST",
                version="1.0.0",
                profiles=[
                    PolicyProfile(
                        profile_id="default",
                        risk_cap=100,
                        confidence_factors={
                            ConfidenceLevel.HIGH: Decimal("1.00"),
                            ConfidenceLevel.MEDIUM: Decimal("0.75"),
                            ConfidenceLevel.LOW: Decimal("0.50"),
                            ConfidenceLevel.NOT_SCORED: Decimal("0.25"),
                        },
                        suppressed_rule_ids=[],
                    )
                ],
                rules=[
                    PolicyRule(
                        rule_id="RULE-001",
                        version="1.0.0",
                        title="Test",
                        category=FindingCategory.ENCRYPTION_TRANSITION,
                        protocols=[Protocol.SMTP],
                        severity=SeverityLevel.HIGH,
                        policy_risk_contribution=25,
                        requires=[FactRequirement(fact="x", operator="equals", value=True)],
                        evidence_requirements=["starttls_advertisement"],
                        rationale="Test",
                        impact="Test",
                        recommendation_id="REC-001",
                        standards_references=[StandardsReference(id="RFC1234")],
                    )
                ],
                recommendations=[
                    RecommendationTemplate(
                        recommendation_id="REC-001",
                        title="Test",
                        summary="Test",
                        priority=RecommendationPriority.HIGH,
                        action_steps=["Step 1"],
                        verification_steps=["Verify 1"],
                        standards_references=[StandardsReference(id="RFC1234")],
                        scope=RecommendationScope.SERVICE,
                        automation_status=AutomationStatus.ADVISORY_ONLY,
                    ),
                    RecommendationTemplate(
                        recommendation_id="REC-ORPHAN",
                        title="Orphan",
                        summary="Orphan",
                        priority=RecommendationPriority.INFO,
                        action_steps=["Step 1"],
                        verification_steps=["Verify 1"],
                        standards_references=[],
                        scope=RecommendationScope.SERVICE,
                        automation_status=AutomationStatus.ADVISORY_ONLY,
                    ),
                ],
            )


class TestPolicyEvaluationContext:
    def test_valid_context(self):
        from datetime import UTC, datetime

        from securemailscope.chain.policy.models import PolicyEvaluationContext

        ctx = PolicyEvaluationContext(
            profile_id="default",
            evaluated_at=datetime(2026, 8, 30, 12, 0, 0, tzinfo=UTC),
            base_configuration_digest="a" * 64,
        )
        assert ctx.profile_id == "default"

    def test_naive_datetime_rejected(self):
        from datetime import datetime

        from securemailscope.chain.policy.models import PolicyEvaluationContext

        with pytest.raises(ValidationError):
            PolicyEvaluationContext(
                profile_id="default",
                evaluated_at=datetime(2026, 8, 30, 12, 0, 0),  # naive
                base_configuration_digest="a" * 64,
            )

    def test_invalid_digest_rejected(self):
        from datetime import UTC, datetime

        from securemailscope.chain.policy.models import PolicyEvaluationContext

        with pytest.raises(ValidationError):
            PolicyEvaluationContext(
                profile_id="default",
                evaluated_at=datetime(2026, 8, 30, 12, 0, 0, tzinfo=UTC),
                base_configuration_digest="x" * 63,  # wrong length
            )
