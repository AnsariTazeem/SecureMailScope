import type { AnalysisResult } from "@/lib/contracts/analysis";
import {
  ProofMapIntegrityError,
  validateProofMapIntegrity,
} from "@/components/analysis/proof-map/proof-map-integrity";

export class FindingsIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FindingsIntegrityError";
  }
}

export function validateFindingsIntegrity(result: AnalysisResult): void {
  try {
    validateProofMapIntegrity(result);
  } catch (error) {
    if (error instanceof ProofMapIntegrityError) {
      throw new FindingsIntegrityError(error.message);
    }
    throw error;
  }

  const { analysis, sessions, findings, evidence, derived_facts, rule_evaluations, recommendations, policy_risk, anomaly_results } =
    result.chain;

  const sessionIds = new Set(sessions.map((s) => s.session_id));
  const evidenceIds = new Set(evidence.map((e) => e.evidence_id));
  const factIds = new Set(derived_facts.map((f) => f.fact_id));
  const evaluationIds = new Set(rule_evaluations.map((e) => e.evaluation_id));
  const recommendationIds = new Set(
    recommendations.map((r) => r.recommendation_id),
  );

  const findingIds = new Set<string>();
  for (const finding of findings) {
    if (findingIds.has(finding.finding_id)) {
      throw new FindingsIntegrityError(
        `Duplicate finding ID: ${finding.finding_id}`,
      );
    }
    findingIds.add(finding.finding_id);

    if (finding.analysis_id !== analysis.analysis_id) {
      throw new FindingsIntegrityError(
        `Finding ${finding.finding_id} references analysis ${finding.analysis_id} but expected ${analysis.analysis_id}`,
      );
    }

    if (!sessionIds.has(finding.session_id)) {
      throw new FindingsIntegrityError(
        `Finding ${finding.finding_id} references unresolved session ${finding.session_id}`,
      );
    }

    if (!evaluationIds.has(finding.rule_evaluation_id)) {
      throw new FindingsIntegrityError(
        `Finding ${finding.finding_id} references unresolved evaluation ${finding.rule_evaluation_id}`,
      );
    }

    for (const factId of finding.fact_ids) {
      if (!factIds.has(factId)) {
        throw new FindingsIntegrityError(
          `Finding ${finding.finding_id} references unresolved fact ${factId}`,
        );
      }
    }

    for (const evidenceId of finding.evidence_ids) {
      if (!evidenceIds.has(evidenceId)) {
        throw new FindingsIntegrityError(
          `Finding ${finding.finding_id} references unresolved evidence ${evidenceId}`,
        );
      }
      const ev = evidence.find((e) => e.evidence_id === evidenceId);
      if (ev && ev.session_id !== finding.session_id) {
        throw new FindingsIntegrityError(
          `Finding ${finding.finding_id} references cross-session evidence ${evidenceId} (finding session: ${finding.session_id}, evidence session: ${ev.session_id})`,
        );
      }
    }

    if (!recommendationIds.has(finding.recommendation_id)) {
      throw new FindingsIntegrityError(
        `Finding ${finding.finding_id} references unresolved recommendation ${finding.recommendation_id}`,
      );
    }
  }

  if (policy_risk) {
    const contributedFindingIds = new Set<string>();
    for (const contrib of policy_risk.contributions) {
      if (!findingIds.has(contrib.finding_id)) {
        throw new FindingsIntegrityError(
          `Policy risk contribution ${contrib.contribution_id} references unresolved finding ${contrib.finding_id}`,
        );
      }
      if (contributedFindingIds.has(contrib.finding_id)) {
        throw new FindingsIntegrityError(
          `Policy finding ${contrib.finding_id} has more than one risk contribution`,
        );
      }
      contributedFindingIds.add(contrib.finding_id);
    }
    for (const findingId of findingIds) {
      if (!contributedFindingIds.has(findingId)) {
        throw new FindingsIntegrityError(
          `Policy finding ${findingId} has no declared risk contribution`,
        );
      }
    }
  } else if (findings.length > 0) {
    throw new FindingsIntegrityError(
      "Policy findings exist without a Policy Risk summary",
    );
  }

  for (const rec of recommendations) {
    for (const findingId of rec.affected_finding_ids) {
      if (!findingIds.has(findingId)) {
        throw new FindingsIntegrityError(
          `Recommendation ${rec.recommendation_id} references unresolved finding ${findingId}`,
        );
      }
    }
  }

  for (const anomaly of anomaly_results) {
    if (!sessionIds.has(anomaly.session_id)) {
      throw new FindingsIntegrityError(
        `Anomaly result ${anomaly.anomaly_result_id} references unresolved session ${anomaly.session_id}`,
      );
    }
    if (
      analysis.model_id === null ||
      analysis.model_version === null ||
      anomaly.model_id !== analysis.model_id ||
      anomaly.model_version !== analysis.model_version
    ) {
      throw new FindingsIntegrityError(
        `Anomaly result ${anomaly.anomaly_result_id} contradicts the analysis model identity`,
      );
    }
  }

  if (
    ["not_run", "failed", "unavailable"].includes(
      analysis.ml_engine_status,
    ) &&
    anomaly_results.length > 0
  ) {
    throw new FindingsIntegrityError(
      `ML engine status ${analysis.ml_engine_status} cannot declare anomaly results`,
    );
  }
}
