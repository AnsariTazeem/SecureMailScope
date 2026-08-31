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

export type SessionXRayIntegrityCode =
  | "duplicate_id"
  | "unresolved_reference"
  | "cross_session_reference"
  | "cross_capture_reference"
  | "capture_hash_mismatch"
  | "relationship_mismatch"
  | "cyclic_fact_sources";

export class SessionXRayIntegrityError extends Error {
  readonly code: SessionXRayIntegrityCode;

  constructor(code: SessionXRayIntegrityCode, message: string) {
    super(message);
    this.name = "SessionXRayIntegrityError";
    this.code = code;
  }
}

export type SessionXRayIntegrityContext = {
  chain: Chain;
  session: Session;
  capture: Capture;
  evidenceById: Map<string, Evidence>;
  eventsById: Map<string, ProtocolEvent>;
  observationsById: Map<string, CryptoObservation>;
  factsById: Map<string, DerivedFact>;
  evaluationsById: Map<string, RuleEvaluation>;
  findingsById: Map<string, Finding>;
  recommendationsById: Map<string, Recommendation>;
  sessionEvidence: Evidence[];
  sessionEvents: ProtocolEvent[];
  sessionObservations: CryptoObservation[];
  sessionFacts: DerivedFact[];
  sessionEvaluations: RuleEvaluation[];
  sessionFindings: Finding[];
  sessionAnomalies: AnomalyResult[];
};

function integrityFailure(
  code: SessionXRayIntegrityCode,
  message: string,
): never {
  throw new SessionXRayIntegrityError(code, message);
}

function uniqueMap<T>(
  records: T[],
  getId: (record: T) => string,
  entityName: string,
): Map<string, T> {
  const result = new Map<string, T>();
  for (const record of records) {
    const id = getId(record);
    if (result.has(id)) {
      integrityFailure("duplicate_id", `Duplicate ${entityName} identifier: ${id}`);
    }
    result.set(id, record);
  }
  return result;
}

function requiredReference<T>(
  records: Map<string, T>,
  id: string,
  entityName: string,
  relationship: string,
): T {
  const record = records.get(id);
  if (!record) {
    integrityFailure(
      "unresolved_reference",
      `${relationship} references an unknown ${entityName}: ${id}`,
    );
  }
  return record;
}

function assertSessionOwnership(
  recordSessionId: string,
  sessionId: string,
  relationship: string,
): void {
  if (recordSessionId !== sessionId) {
    integrityFailure(
      "cross_session_reference",
      `${relationship} crosses the current session boundary.`,
    );
  }
}

export function validateSessionXRayIntegrity(
  result: AnalysisResult,
  sessionId: string,
): SessionXRayIntegrityContext | null {
  const { chain } = result;
  const capturesById = uniqueMap(
    chain.captures,
    (capture) => capture.capture_id,
    "capture",
  );
  const sessionsById = uniqueMap(
    chain.sessions,
    (session) => session.session_id,
    "session",
  );
  const evidenceById = uniqueMap(
    chain.evidence,
    (evidence) => evidence.evidence_id,
    "evidence",
  );
  const eventsById = uniqueMap(
    chain.protocol_events,
    (event) => event.event_id,
    "event",
  );
  const observationsById = uniqueMap(
    chain.crypto_observations,
    (observation) => observation.observation_id,
    "observation",
  );
  const factsById = uniqueMap(
    chain.derived_facts,
    (fact) => fact.fact_id,
    "fact",
  );
  const evaluationsById = uniqueMap(
    chain.rule_evaluations,
    (evaluation) => evaluation.evaluation_id,
    "rule evaluation",
  );
  const findingsById = uniqueMap(
    chain.findings,
    (finding) => finding.finding_id,
    "finding",
  );
  const recommendationsById = uniqueMap(
    chain.recommendations,
    (recommendation) => recommendation.recommendation_id,
    "recommendation",
  );
  uniqueMap(
    chain.anomaly_results,
    (anomaly) => anomaly.anomaly_result_id,
    "anomaly result",
  );

  const session = sessionsById.get(sessionId);
  if (!session) return null;

  const capture = requiredReference(
    capturesById,
    session.capture_id,
    "capture",
    `Session ${session.session_id}`,
  );
  const sessionEvidence = chain.evidence.filter(
    (evidence) => evidence.session_id === sessionId,
  );
  const sessionEvents = chain.protocol_events.filter(
    (event) => event.session_id === sessionId,
  );
  const sessionObservations = chain.crypto_observations.filter(
    (observation) => observation.session_id === sessionId,
  );
  const sessionFacts = chain.derived_facts.filter(
    (fact) => fact.session_id === sessionId,
  );
  const sessionEvaluations = chain.rule_evaluations.filter(
    (evaluation) => evaluation.session_id === sessionId,
  );
  const sessionFindings = chain.findings.filter(
    (finding) => finding.session_id === sessionId,
  );
  const sessionAnomalies = chain.anomaly_results.filter(
    (anomaly) => anomaly.session_id === sessionId,
  );

  const requireSessionEvidence = (
    evidenceId: string,
    relationship: string,
  ): Evidence => {
    const evidence = requiredReference(
      evidenceById,
      evidenceId,
      "evidence",
      relationship,
    );
    assertSessionOwnership(evidence.session_id, sessionId, relationship);
    if (evidence.capture_id !== session.capture_id) {
      integrityFailure(
        "cross_capture_reference",
        `${relationship} references evidence from another capture.`,
      );
    }
    if (evidence.capture_sha256 !== capture.sha256) {
      integrityFailure(
        "capture_hash_mismatch",
        `${relationship} references evidence with a contradictory capture hash.`,
      );
    }
    return evidence;
  };

  for (const evidence of sessionEvidence) {
    if (evidence.capture_id !== session.capture_id) {
      integrityFailure(
        "cross_capture_reference",
        `Evidence ${evidence.evidence_id} does not belong to the session capture.`,
      );
    }
    if (evidence.capture_sha256 !== capture.sha256) {
      integrityFailure(
        "capture_hash_mismatch",
        `Evidence ${evidence.evidence_id} does not match the session capture hash.`,
      );
    }
  }

  for (const evidenceId of session.classification_evidence_ids) {
    requireSessionEvidence(
      evidenceId,
      `Session ${session.session_id} classification evidence`,
    );
  }

  for (const event of sessionEvents) {
    for (const evidenceId of event.evidence_ids) {
      requireSessionEvidence(evidenceId, `Event ${event.event_id}`);
    }
  }

  for (const observation of sessionObservations) {
    for (const evidenceId of observation.evidence_ids) {
      requireSessionEvidence(
        evidenceId,
        `Observation ${observation.observation_id}`,
      );
    }
  }

  for (const fact of sessionFacts) {
    if (
      fact.source_event_ids.length === 0 &&
      fact.source_observation_ids.length === 0 &&
      fact.source_fact_ids.length === 0
    ) {
      integrityFailure(
        "relationship_mismatch",
        `Derived fact ${fact.fact_id} has no declared source.`,
      );
    }
    for (const eventId of fact.source_event_ids) {
      const event = requiredReference(
        eventsById,
        eventId,
        "event",
        `Fact ${fact.fact_id}`,
      );
      assertSessionOwnership(event.session_id, sessionId, `Fact ${fact.fact_id}`);
    }
    for (const observationId of fact.source_observation_ids) {
      const observation = requiredReference(
        observationsById,
        observationId,
        "observation",
        `Fact ${fact.fact_id}`,
      );
      assertSessionOwnership(
        observation.session_id,
        sessionId,
        `Fact ${fact.fact_id}`,
      );
    }
    for (const sourceFactId of fact.source_fact_ids) {
      const sourceFact = requiredReference(
        factsById,
        sourceFactId,
        "fact",
        `Fact ${fact.fact_id}`,
      );
      assertSessionOwnership(
        sourceFact.session_id,
        sessionId,
        `Fact ${fact.fact_id}`,
      );
    }
  }

  const visitingFacts = new Set<string>();
  const visitedFacts = new Set<string>();
  const visitFactSources = (fact: DerivedFact): void => {
    if (visitedFacts.has(fact.fact_id)) return;
    if (visitingFacts.has(fact.fact_id)) {
      integrityFailure(
        "cyclic_fact_sources",
        `Derived fact source cycle includes ${fact.fact_id}.`,
      );
    }
    visitingFacts.add(fact.fact_id);
    for (const sourceFactId of fact.source_fact_ids) {
      visitFactSources(
        requiredReference(
          factsById,
          sourceFactId,
          "fact",
          `Fact ${fact.fact_id}`,
        ),
      );
    }
    visitingFacts.delete(fact.fact_id);
    visitedFacts.add(fact.fact_id);
  };
  for (const fact of sessionFacts) visitFactSources(fact);

  for (const evaluation of sessionEvaluations) {
    for (const factId of evaluation.input_fact_ids) {
      const fact = requiredReference(
        factsById,
        factId,
        "fact",
        `Rule evaluation ${evaluation.evaluation_id}`,
      );
      assertSessionOwnership(
        fact.session_id,
        sessionId,
        `Rule evaluation ${evaluation.evaluation_id}`,
      );
    }
    if (evaluation.generated_finding_id) {
      const finding = requiredReference(
        findingsById,
        evaluation.generated_finding_id,
        "finding",
        `Rule evaluation ${evaluation.evaluation_id}`,
      );
      assertSessionOwnership(
        finding.session_id,
        sessionId,
        `Rule evaluation ${evaluation.evaluation_id}`,
      );
      if (finding.rule_evaluation_id !== evaluation.evaluation_id) {
        integrityFailure(
          "relationship_mismatch",
          `Rule evaluation ${evaluation.evaluation_id} and finding ${finding.finding_id} disagree.`,
        );
      }
    }
  }

  for (const finding of sessionFindings) {
    if (finding.analysis_id !== chain.analysis.analysis_id) {
      integrityFailure(
        "relationship_mismatch",
        `Finding ${finding.finding_id} belongs to another analysis.`,
      );
    }
    for (const factId of finding.fact_ids) {
      const fact = requiredReference(
        factsById,
        factId,
        "fact",
        `Finding ${finding.finding_id}`,
      );
      assertSessionOwnership(fact.session_id, sessionId, `Finding ${finding.finding_id}`);
    }
    for (const evidenceId of finding.evidence_ids) {
      requireSessionEvidence(evidenceId, `Finding ${finding.finding_id}`);
    }

    const evaluation = requiredReference(
      evaluationsById,
      finding.rule_evaluation_id,
      "rule evaluation",
      `Finding ${finding.finding_id}`,
    );
    assertSessionOwnership(
      evaluation.session_id,
      sessionId,
      `Finding ${finding.finding_id}`,
    );
    if (
      evaluation.generated_finding_id !== finding.finding_id ||
      evaluation.rule_id !== finding.rule_id ||
      evaluation.rule_version !== finding.rule_version
    ) {
      integrityFailure(
        "relationship_mismatch",
        `Finding ${finding.finding_id} contradicts its rule evaluation.`,
      );
    }

    const recommendation = requiredReference(
      recommendationsById,
      finding.recommendation_id,
      "recommendation",
      `Finding ${finding.finding_id}`,
    );
    if (!recommendation.affected_finding_ids.includes(finding.finding_id)) {
      integrityFailure(
        "relationship_mismatch",
        `Finding ${finding.finding_id} is absent from its recommendation.`,
      );
    }
  }

  const relevantRecommendations = new Set(
    sessionFindings.map((finding) => finding.recommendation_id),
  );
  for (const recommendationId of relevantRecommendations) {
    const recommendation = requiredReference(
      recommendationsById,
      recommendationId,
      "recommendation",
      `Session ${sessionId}`,
    );
    for (const findingId of recommendation.affected_finding_ids) {
      const affectedFinding = requiredReference(
        findingsById,
        findingId,
        "finding",
        `Recommendation ${recommendation.recommendation_id}`,
      );
      if (affectedFinding.recommendation_id !== recommendation.recommendation_id) {
        integrityFailure(
          "relationship_mismatch",
          `Recommendation ${recommendation.recommendation_id} contradicts finding ${findingId}.`,
        );
      }
    }
  }

  for (const anomaly of sessionAnomalies) {
    for (const factId of anomaly.linked_fact_ids ?? []) {
      const fact = requiredReference(
        factsById,
        factId,
        "fact",
        `Anomaly result ${anomaly.anomaly_result_id}`,
      );
      assertSessionOwnership(
        fact.session_id,
        sessionId,
        `Anomaly result ${anomaly.anomaly_result_id}`,
      );
    }
    for (const observationId of anomaly.linked_observation_ids ?? []) {
      const observation = requiredReference(
        observationsById,
        observationId,
        "observation",
        `Anomaly result ${anomaly.anomaly_result_id}`,
      );
      assertSessionOwnership(
        observation.session_id,
        sessionId,
        `Anomaly result ${anomaly.anomaly_result_id}`,
      );
    }
    for (const evidenceId of anomaly.evidence_ids ?? []) {
      requireSessionEvidence(
        evidenceId,
        `Anomaly result ${anomaly.anomaly_result_id}`,
      );
    }
  }

  return {
    chain,
    session,
    capture,
    evidenceById,
    eventsById,
    observationsById,
    factsById,
    evaluationsById,
    findingsById,
    recommendationsById,
    sessionEvidence,
    sessionEvents,
    sessionObservations,
    sessionFacts,
    sessionEvaluations,
    sessionFindings,
    sessionAnomalies,
  };
}
