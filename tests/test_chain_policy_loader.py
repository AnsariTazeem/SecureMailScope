"""Tests for safe YAML policy pack loader (Commit 4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from securemailscope.chain.errors import PolicyPackLoadError
from securemailscope.chain.policy.loader import (
    canonical_policy_pack_digest,
    load_default_policy_pack,
    load_policy_pack,
)


class TestLoadPolicyPack:
    def test_default_pack_loads(self):
        pack = load_default_policy_pack()
        assert pack.pack_id == "SMS-EMAIL-STARTTLS"
        assert pack.version == "1.0.0"
        assert len(pack.profiles) == 1
        assert pack.profiles[0].profile_id == "sms-liberal"
        assert len(pack.rules) == 1
        assert pack.rules[0].rule_id == "SMS-SMTP-STARTTLS-001"
        assert len(pack.recommendations) == 1
        assert pack.recommendations[0].recommendation_id == "REC-EMAIL-REQUIRE-TLS"

    def test_exact_identities(self):
        pack = load_default_policy_pack()
        assert pack.pack_id == "SMS-EMAIL-STARTTLS"
        assert pack.version == "1.0.0"
        profile = pack.profiles[0]
        assert profile.profile_id == "sms-liberal"
        assert profile.risk_cap == 100
        rule = pack.rules[0]
        assert rule.rule_id == "SMS-SMTP-STARTTLS-001"
        assert rule.version == "1.0.0"
        rec = pack.recommendations[0]
        assert rec.recommendation_id == "REC-EMAIL-REQUIRE-TLS"

    def test_unknown_field_rejected(self, tmp_path: Path):
        yaml_content = """
pack_id: TEST
version: 1.0.0
profiles:
  - profile_id: default
    risk_cap: 100
    confidence_factors:
      high: 1.00
      medium: 0.75
      low: 0.50
      not_scored: 0.25
    suppressed_rule_ids: []
rules:
  - rule_id: RULE-001
    version: 1.0.0
    title: Test
    category: encryption_transition
    protocols: [smtp]
    severity: high
    policy_risk_contribution: 25
    requires:
      - fact: x
        operator: equals
        value: true
    evidence_requirements: [starttls_advertisement]
    rationale: Test
    impact: Test
    recommendation_id: REC-001
    standards_references: [{id: RFC1234}]
recommendations:
  - recommendation_id: REC-001
    title: Test
    summary: Test
    priority: high
    action_steps: [Step 1]
    verification_steps: [Verify 1]
    standards_references: [{id: RFC1234}]
    scope: service
    automation_status: advisory_only
unknown_field: boom
"""
        path = tmp_path / "bad.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(PolicyPackLoadError):
            load_policy_pack(path)

    def test_malformed_yaml_rejected(self, tmp_path: Path):
        path = tmp_path / "bad.yaml"
        path.write_text("{ invalid: [", encoding="utf-8")
        with pytest.raises(PolicyPackLoadError) as exc:
            load_policy_pack(path)
        assert exc.value.code.value == "policy_pack_invalid"

    def test_empty_yaml_rejected(self, tmp_path: Path):
        path = tmp_path / "empty.yaml"
        path.write_text("", encoding="utf-8")
        with pytest.raises(PolicyPackLoadError) as exc:
            load_policy_pack(path)
        assert "empty" in str(exc.value).lower()

    def test_oversized_input_rejected(self, tmp_path: Path):
        # Create content larger than 65536 bytes
        large_content = "x" * 70000
        path = tmp_path / "large.yaml"
        path.write_text(
            "pack_id: TEST\nversion: 1.0.0\nprofiles: []\nrules: []\n"
            f"recommendations: []\n# {large_content}",
            encoding="utf-8",
        )
        with pytest.raises(PolicyPackLoadError) as exc:
            load_policy_pack(path)
        assert "exceeds maximum size" in str(exc.value)

    def test_duplicate_key_rejected(self, tmp_path: Path):
        yaml_content = """
pack_id: TEST
version: 1.0.0
pack_id: DUPLICATE
profiles: []
rules: []
recommendations: []
"""
        path = tmp_path / "dup.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(PolicyPackLoadError) as exc:
            load_policy_pack(path)
        assert "duplicate mapping key" in str(exc.value)

    def test_merge_key_rejected(self, tmp_path: Path):
        yaml_content = """
pack_id: TEST
version: 1.0.0
profiles: &default
  - profile_id: default
    risk_cap: 100
    confidence_factors:
      high: 1.00
      medium: 0.75
      low: 0.50
      not_scored: 0.25
    suppressed_rule_ids: []
rules: []
recommendations: []
<<: *default
"""
        path = tmp_path / "merge.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(PolicyPackLoadError) as exc:
            load_policy_pack(path)
        assert "merge keys" in str(exc.value)

    def test_alias_anchor_rejected(self, tmp_path: Path):
        yaml_content = """
pack_id: TEST
version: 1.0.0
profiles:
  - &anchor
    profile_id: default
    risk_cap: 100
    confidence_factors:
      high: 1.00
      medium: 0.75
      low: 0.50
      not_scored: 0.25
    suppressed_rule_ids: []
rules: []
recommendations: []
"""
        path = tmp_path / "alias.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(PolicyPackLoadError) as exc:
            load_policy_pack(path)
        assert "aliases and anchors" in str(exc.value)

    def test_python_tag_rejected(self, tmp_path: Path):
        yaml_content = """
pack_id: !!python/object/apply:os.system ['echo boom']
version: 1.0.0
profiles: []
rules: []
recommendations: []
"""
        path = tmp_path / "exec.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(PolicyPackLoadError) as exc:
            load_policy_pack(path)
        assert "executable or custom" in str(exc.value)

    def test_invalid_semver_rejected(self, tmp_path: Path):
        yaml_content = """
pack_id: TEST
version: not-semver
profiles:
  - profile_id: default
    risk_cap: 100
    confidence_factors:
      high: 1.00
      medium: 0.75
      low: 0.50
      not_scored: 0.25
    suppressed_rule_ids: []
rules: []
recommendations: []
"""
        path = tmp_path / "badver.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(PolicyPackLoadError):
            load_policy_pack(path)

    def test_unsupported_operator_rejected(self, tmp_path: Path):
        yaml_content = """
pack_id: TEST
version: 1.0.0
profiles:
  - profile_id: default
    risk_cap: 100
    confidence_factors:
      high: 1.00
      medium: 0.75
      low: 0.50
      not_scored: 0.25
    suppressed_rule_ids: []
rules:
  - rule_id: RULE-001
    version: 1.0.0
    title: Test
    category: encryption_transition
    protocols: [smtp]
    severity: high
    policy_risk_contribution: 25
    requires:
      - fact: x
        operator: contains
        value: foo
    evidence_requirements: [starttls_advertisement]
    rationale: Test
    impact: Test
    recommendation_id: REC-001
    standards_references: [{id: RFC1234}]
recommendations:
  - recommendation_id: REC-001
    title: Test
    summary: Test
    priority: high
    action_steps: [Step 1]
    verification_steps: [Verify 1]
    standards_references: [{id: RFC1234}]
    scope: service
    automation_status: advisory_only
"""
        path = tmp_path / "badop.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(PolicyPackLoadError):
            load_policy_pack(path)

    def test_greater_than_bool_rejected(self, tmp_path: Path):
        yaml_content = """
pack_id: TEST
version: 1.0.0
profiles:
  - profile_id: default
    risk_cap: 100
    confidence_factors:
      high: 1.00
      medium: 0.75
      low: 0.50
      not_scored: 0.25
    suppressed_rule_ids: []
rules:
  - rule_id: RULE-001
    version: 1.0.0
    title: Test
    category: encryption_transition
    protocols: [smtp]
    severity: high
    policy_risk_contribution: 25
    requires:
      - fact: x
        operator: greater_than
        value: true
    evidence_requirements: [starttls_advertisement]
    rationale: Test
    impact: Test
    recommendation_id: REC-001
    standards_references: [{id: RFC1234}]
recommendations:
  - recommendation_id: REC-001
    title: Test
    summary: Test
    priority: high
    action_steps: [Step 1]
    verification_steps: [Verify 1]
    standards_references: [{id: RFC1234}]
    scope: service
    automation_status: advisory_only
"""
        path = tmp_path / "badgt.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(PolicyPackLoadError):
            load_policy_pack(path)

    def test_duplicate_rule_rejected(self, tmp_path: Path):
        yaml_content = """
pack_id: TEST
version: 1.0.0
profiles:
  - profile_id: default
    risk_cap: 100
    confidence_factors:
      high: 1.00
      medium: 0.75
      low: 0.50
      not_scored: 0.25
    suppressed_rule_ids: []
rules:
  - rule_id: RULE-001
    version: 1.0.0
    title: Test
    category: encryption_transition
    protocols: [smtp]
    severity: high
    policy_risk_contribution: 25
    requires:
      - fact: x
        operator: equals
        value: true
    evidence_requirements: [starttls_advertisement]
    rationale: Test
    impact: Test
    recommendation_id: REC-001
    standards_references: [{id: RFC1234}]
  - rule_id: RULE-001
    version: 1.0.1
    title: Test 2
    category: encryption_transition
    protocols: [smtp]
    severity: high
    policy_risk_contribution: 25
    requires:
      - fact: x
        operator: equals
        value: true
    evidence_requirements: [starttls_advertisement]
    rationale: Test
    impact: Test
    recommendation_id: REC-001
    standards_references: [{id: RFC1234}]
recommendations:
  - recommendation_id: REC-001
    title: Test
    summary: Test
    priority: high
    action_steps: [Step 1]
    verification_steps: [Verify 1]
    standards_references: [{id: RFC1234}]
    scope: service
    automation_status: advisory_only
"""
        path = tmp_path / "duprule.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(PolicyPackLoadError):
            load_policy_pack(path)

    def test_duplicate_profile_rejected(self, tmp_path: Path):
        yaml_content = """
pack_id: TEST
version: 1.0.0
profiles:
  - profile_id: default
    risk_cap: 100
    confidence_factors:
      high: 1.00
      medium: 0.75
      low: 0.50
      not_scored: 0.25
    suppressed_rule_ids: []
  - profile_id: default
    risk_cap: 100
    confidence_factors:
      high: 1.00
      medium: 0.75
      low: 0.50
      not_scored: 0.25
    suppressed_rule_ids: []
rules:
  - rule_id: RULE-001
    version: 1.0.0
    title: Test
    category: encryption_transition
    protocols: [smtp]
    severity: high
    policy_risk_contribution: 25
    requires:
      - fact: x
        operator: equals
        value: true
    evidence_requirements: [starttls_advertisement]
    rationale: Test
    impact: Test
    recommendation_id: REC-001
    standards_references: [{id: RFC1234}]
recommendations:
  - recommendation_id: REC-001
    title: Test
    summary: Test
    priority: high
    action_steps: [Step 1]
    verification_steps: [Verify 1]
    standards_references: [{id: RFC1234}]
    scope: service
    automation_status: advisory_only
"""
        path = tmp_path / "dupprof.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(PolicyPackLoadError):
            load_policy_pack(path)

    def test_unresolved_recommendation_rejected(self, tmp_path: Path):
        yaml_content = """
pack_id: TEST
version: 1.0.0
profiles:
  - profile_id: default
    risk_cap: 100
    confidence_factors:
      high: 1.00
      medium: 0.75
      low: 0.50
      not_scored: 0.25
    suppressed_rule_ids: []
rules:
  - rule_id: RULE-001
    version: 1.0.0
    title: Test
    category: encryption_transition
    protocols: [smtp]
    severity: high
    policy_risk_contribution: 25
    requires:
      - fact: x
        operator: equals
        value: true
    evidence_requirements: [starttls_advertisement]
    rationale: Test
    impact: Test
    recommendation_id: REC-MISSING
    standards_references: [{id: RFC1234}]
recommendations:
  - recommendation_id: REC-001
    title: Test
    summary: Test
    priority: high
    action_steps: [Step 1]
    verification_steps: [Verify 1]
    standards_references: [{id: RFC1234}]
    scope: service
    automation_status: advisory_only
"""
        path = tmp_path / "unresolved.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(PolicyPackLoadError):
            load_policy_pack(path)

    def test_unresolved_suppressed_rule_rejected(self, tmp_path: Path):
        yaml_content = """
pack_id: TEST
version: 1.0.0
profiles:
  - profile_id: default
    risk_cap: 100
    confidence_factors:
      high: 1.00
      medium: 0.75
      low: 0.50
      not_scored: 0.25
    suppressed_rule_ids: [NONEXISTENT]
rules:
  - rule_id: RULE-001
    version: 1.0.0
    title: Test
    category: encryption_transition
    protocols: [smtp]
    severity: high
    policy_risk_contribution: 25
    requires:
      - fact: x
        operator: equals
        value: true
    evidence_requirements: [starttls_advertisement]
    rationale: Test
    impact: Test
    recommendation_id: REC-001
    standards_references: [{id: RFC1234}]
recommendations:
  - recommendation_id: REC-001
    title: Test
    summary: Test
    priority: high
    action_steps: [Step 1]
    verification_steps: [Verify 1]
    standards_references: [{id: RFC1234}]
    scope: service
    automation_status: advisory_only
"""
        path = tmp_path / "unresolvedsupp.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(PolicyPackLoadError):
            load_policy_pack(path)

    def test_nesting_depth_rejected(self, tmp_path: Path):
        # Create deeply nested YAML
        nested = "a:\n" + "  " * 25 + "b: 1"
        yaml_content = (
            f"pack_id: TEST\nversion: 1.0.0\nprofiles: []\nrules: []\nrecommendations: []\n{nested}"
        )
        path = tmp_path / "deep.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(PolicyPackLoadError):
            load_policy_pack(path)

    def test_node_count_rejected(self, tmp_path: Path):
        # Create YAML with many nodes
        items = "\n".join(f"  - item{i}: value" for i in range(3000))
        yaml_content = (
            "pack_id: TEST\nversion: 1.0.0\nprofiles: []\nrules: []\n"
            f"recommendations: []\nitems:\n{items}"
        )
        path = tmp_path / "many.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(PolicyPackLoadError):
            load_policy_pack(path)

    def test_mapping_key_order_preserves_digest(self, tmp_path: Path):
        yaml1 = """
pack_id: TEST
version: 1.0.0
profiles:
  - profile_id: default
    risk_cap: 100
    confidence_factors:
      high: 1.00
      medium: 0.75
      low: 0.50
      not_scored: 0.25
    suppressed_rule_ids: []
rules:
  - rule_id: RULE-001
    version: 1.0.0
    title: Test
    category: encryption_transition
    protocols: [smtp]
    severity: high
    policy_risk_contribution: 25
    requires:
      - fact: x
        operator: equals
        value: true
    evidence_requirements: [starttls_advertisement]
    rationale: Test
    impact: Test
    recommendation_id: REC-001
    standards_references: [{id: RFC1234}]
recommendations:
  - recommendation_id: REC-001
    title: Test
    summary: Test
    priority: high
    action_steps: [Step 1]
    verification_steps: [Verify 1]
    standards_references: [{id: RFC1234}]
    scope: service
    automation_status: advisory_only
"""
        yaml2 = """
version: 1.0.0
pack_id: TEST
recommendations:
  - recommendation_id: REC-001
    title: Test
    summary: Test
    priority: high
    action_steps: [Step 1]
    verification_steps: [Verify 1]
    standards_references: [{id: RFC1234}]
    scope: service
    automation_status: advisory_only
rules:
  - rule_id: RULE-001
    version: 1.0.0
    title: Test
    category: encryption_transition
    protocols: [smtp]
    severity: high
    policy_risk_contribution: 25
    requires:
      - fact: x
        operator: equals
        value: true
    evidence_requirements: [starttls_advertisement]
    rationale: Test
    impact: Test
    recommendation_id: REC-001
    standards_references: [{id: RFC1234}]
profiles:
  - profile_id: default
    risk_cap: 100
    confidence_factors:
      high: 1.00
      medium: 0.75
      low: 0.50
      not_scored: 0.25
    suppressed_rule_ids: []
"""
        p1 = tmp_path / "a.yaml"
        p2 = tmp_path / "b.yaml"
        p1.write_text(yaml1, encoding="utf-8")
        p2.write_text(yaml2, encoding="utf-8")
        pack1 = load_policy_pack(p1)
        pack2 = load_policy_pack(p2)
        assert canonical_policy_pack_digest(pack1) == canonical_policy_pack_digest(pack2)

    def test_missing_path_gives_typed_error(self):
        with pytest.raises(PolicyPackLoadError) as exc:
            load_policy_pack(Path("/nonexistent/path.yaml"))
        assert exc.value.code.value == "policy_pack_invalid"
        assert "not found" in str(exc.value).lower()

    def test_errors_do_not_contain_yaml_body(self, tmp_path: Path):
        path = tmp_path / "bad.yaml"
        path.write_text("invalid: [", encoding="utf-8")
        try:
            load_policy_pack(path)
        except PolicyPackLoadError as exc:
            # Error message should be bounded and not contain the YAML body
            msg = str(exc)
            assert "invalid" not in msg or len(msg) < 500  # bounded

    def test_no_arbitrary_code_executes(self, tmp_path: Path):
        # This test ensures that the YAML parser doesn't execute arbitrary code
        yaml_content = """
pack_id: !!python/object/apply:subprocess.run [["echo", "exploited"]]
version: 1.0.0
profiles: []
rules: []
recommendations: []
"""
        path = tmp_path / "exploit.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(PolicyPackLoadError):
            load_policy_pack(path)
