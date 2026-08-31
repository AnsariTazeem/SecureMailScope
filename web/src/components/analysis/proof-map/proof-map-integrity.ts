import type { AnalysisResult } from "@/lib/contracts/analysis";

type Chain = AnalysisResult["chain"];
type Capture = Chain["captures"][number];
type Session = Chain["sessions"][number];
type Evidence = Chain["evidence"][number];
type ProtocolEvent = Chain["protocol_events"][number];
type CryptoObservation = Chain["crypto_observations"][number];
type DerivedFact = Chain["derived_facts"][number];
type RuleEvaluation = Chain["rule_evaluations"][number];
type Finding = Chain["findings"][number];
type Recommendation = Chain["recommendations"][number];
type AnomalyResult = Chain["anomaly_results"][number];

export type ProofMapIntegrityCode =
  | "duplicate_id"
  | "unresolved_reference"
  | "cross_session_reference"
  | "cross_capture_reference"
  | "capture_hash_mismatch"
  | "relationship_mismatch"
  | "cyclic_fact_sources";

export class ProofMapIntegrityError extends Error {
  readonly code: ProofMapIntegrityCode;

  constructor(code: ProofMapIntegrityCode, message: string) {
    super(message);
    this.name = "ProofMapIntegrityError";
    this.code = code;
  }
}

export type ProofMapIntegrityContext = {
  chain: Chain;
  capturesById: Map<string, Capture>;
  sessionsById: Map<string, Session>;
  evidenceById: Map<string, Evidence>;
  eventsById: Map<string, ProtocolEvent>;
  observationsById: Map<string, CryptoObservation>;
  factsById: Map<string, DerivedFact>;
  evaluationsById: Map<string, RuleEvaluation>;
  findingsById: Map<string, Finding>;
  recommendationsById: Map<string, Recommendation>;
  anomaliesById: Map<string, AnomalyResult>;
};

function fail(code: ProofMapIntegrityCode, message: string): never {
  throw new ProofMapIntegrityError(code, message);
}

function uniqueMap<T>(
  records: T[],
  getId: (record: T) => string,
  name: string,
): Map<string, T> {
  const result = new Map<string, T>();
  for (const record of records) {
    const id = getId(record);
    if (result.has(id)) fail("duplicate_id", `Duplicate ${name} identifier: ${id}`);
    result.set(id, record);
  }
  return result;
}

function requireReference<T>(
  records: Map<string, T>,
  id: string,
  name: string,
  relationship: string,
): T {
  const record = records.get(id);
  if (!record) {
    fail(
      "unresolved_reference",
      `${relationship} references an unknown ${name}: ${id}`,
    );
  }
  return record;
}

function assertSession(
  recordSessionId: string,
  expectedSessionId: string,
  relationship: string,
): void {
  if (recordSessionId !== expectedSessionId) {
    fail(
      "cross_session_reference",
      `${relationship} crosses a declared session boundary.`,
    );
  }
}

export function validateProofMapIntegrity(
  result: AnalysisResult,
): ProofMapIntegrityContext {
  const { chain } = result;
  const capturesById = uniqueMap(
    chain.captures,
    (record) => record.capture_id,
    "capture",
  );
  const sessionsById = uniqueMap(
    chain.sessions,
    (record) => record.session_id,
    "session",
  );
  const evidenceById = uniqueMap(
    chain.evidence,
    (record) => record.evidence_id,
    "evidence",
  );
  const eventsById = uniqueMap(
    chain.protocol_events,
    (record) => record.event_id,
    "event",
  );
  const observationsById = uniqueMap(
    chain.crypto_observations,
    (record) => record.observation_id,
    "observation",
  );
  const factsById = uniqueMap(
    chain.derived_facts,
    (record) => record.fact_id,
    "fact",
  );
  const evaluationsById = uniqueMap(
    chain.rule_evaluations,
    (record) => record.evaluation_id,
    "rule evaluation",
  );
  const findingsById = uniqueMap(
    chain.findings,
    (record) => record.finding_id,
    "finding",
  );
  const recommendationsById = uniqueMap(
    chain.recommendations,
    (record) => record.recommendation_id,
    "recommendation",
  );
  const anomaliesById = uniqueMap(
    chain.anomaly_results,
    (record) => record.anomaly_result_id,
    "anomaly result",
  );

  const evidenceForSession = (
    evidenceId: string,
    session: Session,
    relationship: string,
  ): Evidence => {
    const evidence = requireReference(
      evidenceById,
      evidenceId,
      "evidence",
      relationship,
    );
    assertSession(evidence.session_id, session.session_id, relationship);
    if (evidence.capture_id !== session.capture_id) {
      fail(
        "cross_capture_reference",
        `${relationship} references evidence from another capture.`,
      );
    }
    const capture = requireReference(
      capturesById,
      session.capture_id,
      "capture",
      `Session ${session.session_id}`,
    );
    if (evidence.capture_sha256 !== capture.sha256) {
      fail(
        "capture_hash_mismatch",
        `${relationship} references evidence with a contradictory capture hash.`,
      );
    }
    return evidence;
  };

  for (const session of chain.sessions) {
    requireReference(
      capturesById,
      session.capture_id,
      "capture",
      `Session ${session.session_id}`,
    );
    for (const evidenceId of session.classification_evidence_ids) {
      evidenceForSession(
        evidenceId,
        session,
        `Session ${session.session_id} classification evidence`,
      );
    }
  }

  for (const evidence of chain.evidence) {
    const session = requireReference(
      sessionsById,
      evidence.session_id,
      "session",
      `Evidence ${evidence.evidence_id}`,
    );
    evidenceForSession(evidence.evidence_id, session, `Evidence ${evidence.evidence_id}`);
  }

  for (const event of chain.protocol_events) {
    const session = requireReference(
      sessionsById,
      event.session_id,
      "session",
      `Event ${event.event_id}`,
    );
    for (const evidenceId of event.evidence_ids) {
      evidenceForSession(evidenceId, session, `Event ${event.event_id}`);
    }
  }

  for (const observation of chain.crypto_observations) {
    const session = requireReference(
      sessionsById,
      observation.session_id,
      "session",
      `Observation ${observation.observation_id}`,
    );
    for (const evidenceId of observation.evidence_ids) {
      evidenceForSession(
        evidenceId,
        session,
        `Observation ${observation.observation_id}`,
      );
    }
  }

  for (const fact of chain.derived_facts) {
    requireReference(
      sessionsById,
      fact.session_id,
      "session",
      `Fact ${fact.fact_id}`,
    );
    if (
      fact.source_event_ids.length === 0 &&
      fact.source_observation_ids.length === 0 &&
      fact.source_fact_ids.length === 0
    ) {
      fail(
        "relationship_mismatch",
        `Derived fact ${fact.fact_id} has no declared source.`,
      );
    }
    for (const eventId of fact.source_event_ids) {
      const event = requireReference(eventsById, eventId, "event", `Fact ${fact.fact_id}`);
      assertSession(event.session_id, fact.session_id, `Fact ${fact.fact_id}`);
    }
    for (const observationId of fact.source_observation_ids) {
      const observation = requireReference(
        observationsById,
        observationId,
        "observation",
        `Fact ${fact.fact_id}`,
      );
      assertSession(
        observation.session_id,
        fact.session_id,
        `Fact ${fact.fact_id}`,
      );
    }
    for (const sourceFactId of fact.source_fact_ids) {
      const sourceFact = requireReference(
        factsById,
        sourceFactId,
        "fact",
        `Fact ${fact.fact_id}`,
      );
      assertSession(sourceFact.session_id, fact.session_id, `Fact ${fact.fact_id}`);
    }
  }

  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visitFact = (fact: DerivedFact): void => {
    if (visited.has(fact.fact_id)) return;
    if (visiting.has(fact.fact_id)) {
      fail(
        "cyclic_fact_sources",
        `Derived fact source cycle includes ${fact.fact_id}.`,
      );
    }
    visiting.add(fact.fact_id);
    for (const sourceFactId of fact.source_fact_ids) {
      visitFact(factsById.get(sourceFactId)!);
    }
    visiting.delete(fact.fact_id);
    visited.add(fact.fact_id);
  };
  for (const fact of chain.derived_facts) visitFact(fact);

  for (const evaluation of chain.rule_evaluations) {
    requireReference(
      sessionsById,
      evaluation.session_id,
      "session",
      `Rule evaluation ${evaluation.evaluation_id}`,
    );
    for (const factId of evaluation.input_fact_ids) {
      const fact = requireReference(
        factsById,
        factId,
        "fact",
        `Rule evaluation ${evaluation.evaluation_id}`,
      );
      assertSession(
        fact.session_id,
        evaluation.session_id,
        `Rule evaluation ${evaluation.evaluation_id}`,
      );
    }
    if (evaluation.generated_finding_id) {
      const finding = requireReference(
        findingsById,
        evaluation.generated_finding_id,
        "finding",
        `Rule evaluation ${evaluation.evaluation_id}`,
      );
      assertSession(
        finding.session_id,
        evaluation.session_id,
        `Rule evaluation ${evaluation.evaluation_id}`,
      );
      if (finding.rule_evaluation_id !== evaluation.evaluation_id) {
        fail(
          "relationship_mismatch",
          `Rule evaluation ${evaluation.evaluation_id} and finding ${finding.finding_id} disagree.`,
        );
      }
    }
  }

  for (const finding of chain.findings) {
    const session = requireReference(
      sessionsById,
      finding.session_id,
      "session",
      `Finding ${finding.finding_id}`,
    );
    if (finding.analysis_id !== chain.analysis.analysis_id) {
      fail(
        "relationship_mismatch",
        `Finding ${finding.finding_id} belongs to another analysis.`,
      );
    }
    for (const factId of finding.fact_ids) {
      const fact = requireReference(factsById, factId, "fact", `Finding ${finding.finding_id}`);
      assertSession(fact.session_id, finding.session_id, `Finding ${finding.finding_id}`);
    }
    for (const evidenceId of finding.evidence_ids) {
      evidenceForSession(evidenceId, session, `Finding ${finding.finding_id}`);
    }
    const evaluation = requireReference(
      evaluationsById,
      finding.rule_evaluation_id,
      "rule evaluation",
      `Finding ${finding.finding_id}`,
    );
    assertSession(evaluation.session_id, finding.session_id, `Finding ${finding.finding_id}`);
    if (
      evaluation.generated_finding_id !== finding.finding_id ||
      evaluation.rule_id !== finding.rule_id ||
      evaluation.rule_version !== finding.rule_version
    ) {
      fail(
        "relationship_mismatch",
        `Finding ${finding.finding_id} contradicts its rule evaluation.`,
      );
    }
    const recommendation = requireReference(
      recommendationsById,
      finding.recommendation_id,
      "recommendation",
      `Finding ${finding.finding_id}`,
    );
    if (!recommendation.affected_finding_ids.includes(finding.finding_id)) {
      fail(
        "relationship_mismatch",
        `Finding ${finding.finding_id} is absent from its recommendation.`,
      );
    }
  }

  for (const recommendation of chain.recommendations) {
    for (const findingId of recommendation.affected_finding_ids) {
      const finding = requireReference(
        findingsById,
        findingId,
        "finding",
        `Recommendation ${recommendation.recommendation_id}`,
      );
      if (finding.recommendation_id !== recommendation.recommendation_id) {
        fail(
          "relationship_mismatch",
          `Recommendation ${recommendation.recommendation_id} contradicts finding ${findingId}.`,
        );
      }
    }
  }

  if (chain.policy_risk) {
    if (chain.policy_risk.analysis_id !== chain.analysis.analysis_id) {
      fail("relationship_mismatch", "Policy Risk belongs to another analysis.");
    }
    uniqueMap(
      chain.policy_risk.contributions,
      (record) => record.contribution_id,
      "Policy Risk contribution",
    );
    for (const contribution of chain.policy_risk.contributions) {
      const finding = requireReference(
        findingsById,
        contribution.finding_id,
        "finding",
        `Policy Risk contribution ${contribution.contribution_id}`,
      );
      if (
        contribution.rule_id !== finding.rule_id ||
        contribution.rule_version !== finding.rule_version ||
        contribution.severity !== finding.severity ||
        contribution.policy_risk_contribution !==
          finding.policy_risk_contribution ||
        contribution.evidence_confidence !== finding.evidence_confidence
      ) {
        fail(
          "relationship_mismatch",
          `Policy Risk contribution ${contribution.contribution_id} contradicts finding ${finding.finding_id}.`,
        );
      }
    }
  }

  for (const anomaly of chain.anomaly_results) {
    const session = requireReference(
      sessionsById,
      anomaly.session_id,
      "session",
      `Anomaly result ${anomaly.anomaly_result_id}`,
    );
    for (const factId of anomaly.linked_fact_ids ?? []) {
      const fact = requireReference(
        factsById,
        factId,
        "fact",
        `Anomaly result ${anomaly.anomaly_result_id}`,
      );
      assertSession(fact.session_id, anomaly.session_id, `Anomaly result ${anomaly.anomaly_result_id}`);
    }
    for (const observationId of anomaly.linked_observation_ids ?? []) {
      const observation = requireReference(
        observationsById,
        observationId,
        "observation",
        `Anomaly result ${anomaly.anomaly_result_id}`,
      );
      assertSession(
        observation.session_id,
        anomaly.session_id,
        `Anomaly result ${anomaly.anomaly_result_id}`,
      );
    }
    for (const evidenceId of anomaly.evidence_ids ?? []) {
      evidenceForSession(
        evidenceId,
        session,
        `Anomaly result ${anomaly.anomaly_result_id}`,
      );
    }
  }

  return {
    chain,
    capturesById,
    sessionsById,
    evidenceById,
    eventsById,
    observationsById,
    factsById,
    evaluationsById,
    findingsById,
    recommendationsById,
    anomaliesById,
  };
}
