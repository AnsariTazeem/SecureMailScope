// Dependency-free verification harness using the project's existing TypeScript compiler.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import Module, { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const load = createRequire(import.meta.url);
const ts = load("typescript");
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../src");
const originalResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...args) {
  return originalResolve.call(this, request.startsWith("@/") ? path.join(root, request.slice(2)) : request, ...args);
};
Module._extensions[".ts"] = function (module, filename) {
  const compiled = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true, resolveJsonModule: true },
    fileName: filename,
  });
  module._compile(compiled.outputText, filename);
};

const { loadPrototypeAnalysisDataset } = load(path.join(root, "mocks/load-prototype-dataset.ts"));
const { buildProofMapData } = load(path.join(root, "components/analysis/proof-map/proof-map-view-model.ts"));
const { buildSessionXRayData } = load(path.join(root, "components/analysis/session-xray/session-xray-view-model.ts"));
const { validateFindingsIntegrity } = load(path.join(root, "components/analysis/findings/findings-integrity.ts"));
const { buildPolicyFindingsData, buildAnomalyFindingsData } = load(path.join(root, "components/analysis/findings/findings-view-model.ts"));
const { selectRecommendations } = load(path.join(root, "components/analysis/recommendations/recommendations-view-model.ts"));
const result = loadPrototypeAnalysisDataset();
const before = JSON.stringify(result);
const graph = buildProofMapData(result);
validateFindingsIntegrity(result);
const policy = buildPolicyFindingsData(result);
assert.equal(policy.findings.length, result.chain.findings.length);
assert.equal(policy.analysisSessions.length, result.chain.sessions.length);
assert.equal(buildAnomalyFindingsData(result).mlEngineStatus, "complete");
assert.equal(buildAnomalyFindingsData(result).results.length, 2);
const notRun = structuredClone(result);
notRun.chain.analysis.ml_engine_status = "not_run";
notRun.chain.anomaly_results = [];
assert.equal(buildAnomalyFindingsData(notRun).mlEngineStatus, "not_run");
assert.equal(buildAnomalyFindingsData(notRun).results.length, 0);
for (const session of result.chain.sessions) {
  const data = buildSessionXRayData(result, session.session_id);
  assert.equal(data.sessionId, session.session_id);
  const nodes = new Set(graph.graphNodes.filter(node => node.sessionIds.includes(session.session_id)).map(node => node.id));
  for (const edge of graph.graphEdges.filter(edge => edge.sessionId === session.session_id)) {
    assert.ok(nodes.has(edge.fromId) && nodes.has(edge.toId), "Session graph must retain both endpoints");
  }
  assert.equal(data.evidence.length, result.chain.evidence.filter(item => item.session_id === session.session_id).length);
}
for (const finding of policy.findings) {
  const declared = result.chain.recommendations.find(item => item.recommendation_id === finding.recommendationId);
  assert.deepEqual(finding.recommendation?.actionSteps, declared?.action_steps);
  assert.deepEqual(finding.recommendation?.verificationSteps, declared?.verification_steps);
}
const allRecommendations = selectRecommendations(policy, null);
assert.equal(allRecommendations.filterState, "all");
assert.equal(allRecommendations.groups.length, result.chain.recommendations.length);
assert.deepEqual(
  allRecommendations.groups.map(group => group.recommendation.recommendationId),
  result.chain.recommendations.map(recommendation => recommendation.recommendation_id),
  "Unfiltered recommendations must preserve supplied contract ordering",
);
const affectedSessionId = policy.findings[0].linkedSessions[0].sessionId;
const affectedSelection = selectRecommendations(policy, affectedSessionId);
assert.equal(affectedSelection.filterState, "valid");
assert.equal(affectedSelection.groups.length, 1);
const emptySession = policy.analysisSessions.find(
  session => !policy.findings.some(finding => finding.linkedSessions.some(link => link.sessionId === session.sessionId)),
);
assert.ok(emptySession, "Prototype data should contain a valid session with no linked finding");
const emptySelection = selectRecommendations(policy, emptySession.sessionId);
assert.equal(emptySelection.filterState, "valid");
assert.equal(emptySelection.groups.length, 0);
const invalidSelection = selectRecommendations(policy, "ses_ffffffffffffffff");
assert.equal(invalidSelection.filterState, "invalid");
assert.equal(invalidSelection.groups.length, 0, "Invalid filters must fail closed");
const multiSessionPolicy = structuredClone(policy);
multiSessionPolicy.findings[0].linkedSessions.push(emptySession);
const multiSessionSelection = selectRecommendations(multiSessionPolicy, affectedSessionId);
assert.deepEqual(
  multiSessionSelection.groups[0].linkedSessions.map(session => session.sessionId),
  [affectedSessionId, emptySession.sessionId],
  "A filtered multi-session recommendation must retain every explicit session destination",
);
const unlinkedRecommendationPolicy = structuredClone(policy);
unlinkedRecommendationPolicy.recommendations.push({
  recommendationId: "REC-UNLINKED-SUPPLIED",
  title: "Supplied unlinked action",
  summary: "Display-only regression record",
  priority: "low",
  actionSteps: ["Exact action"],
  verificationSteps: ["Exact verification"],
  standardsReferences: [],
  scope: "service",
  automationStatus: "advisory_only",
});
const unlinkedSelection = selectRecommendations(unlinkedRecommendationPolicy, null);
assert.equal(unlinkedSelection.groups.at(-1).recommendation.recommendationId, "REC-UNLINKED-SUPPLIED");
assert.equal(unlinkedSelection.groups.at(-1).linkedFindings.length, 0);
assert.equal(JSON.stringify(result), before, "Display projections must not mutate the result");
assert.equal(buildSessionXRayData(result, "ses_ffffffffffffffff"), null);
const duplicate = structuredClone(result);
duplicate.chain.evidence.push(duplicate.chain.evidence[0]);
assert.throws(() => buildProofMapData(duplicate), /Duplicate/);
const crossSession = structuredClone(result);
crossSession.chain.evidence[0].session_id = crossSession.chain.sessions.find(s => s.session_id !== crossSession.chain.evidence[0].session_id).session_id;
assert.throws(() => buildProofMapData(crossSession));
const invalidRecommendation = structuredClone(result);
invalidRecommendation.chain.recommendations = [];
assert.throws(() => validateFindingsIntegrity(invalidRecommendation));
console.log("PASS: session/evidence identity, scoped graph endpoints, exact recommendation steps, recommendation filter and multi-session navigation identity, no mutation, ML not_run, missing session, duplicate and cross-session evidence rejection, unresolved recommendation rejection.");

// Synthetic presentation variants stay in memory; source fixtures are untouched.
const { stateFromEvent, orderProtocolEvents } = load(path.join(root, "components/analysis/session-xray/session-xray-view-model.ts"));
const { analysisResultSchema } = load(path.join(root, "lib/contracts/analysis.ts"));
for (const [event_status, observability, expected] of [
  ["observed", "observed", "observed"], ["inferred", "observed", "derived"],
  ["observed", "derived", "derived"], ["incomplete_capture", "observed", "incomplete"],
  ["not_observable", "observed", "not_observable"],
  ["inferred", "session_secrets_required", "not_observable"],
  ["observed", "not_applicable", "not_applicable"],
]) assert.equal(stateFromEvent({ event_status, observability }), expected);
for (const session of result.chain.sessions) {
  const data = buildSessionXRayData(result, session.session_id);
  const source = result.chain.protocol_events.filter(event => event.session_id === session.session_id);
  assert.deepEqual(data.events.map(event => event.eventId), orderProtocolEvents(source).map(event => event.event_id));
  for (const event of data.events) {
    const declared = source.find(item => item.event_id === event.eventId);
    assert.deepEqual([event.timestamp, event.eventStatus, event.observability, event.stateBefore, event.stateAfter],
      [declared.timestamp, declared.event_status, declared.observability, declared.state_before, declared.state_after]);
    assert.deepEqual(event.evidence.map(item => item.evidenceId), declared.evidence_ids);
    assert.deepEqual(event.frameNumbers, declared.evidence_ids.flatMap(id => result.chain.evidence.find(item => item.evidence_id === id).frame_numbers));
    assert.ok(event.evidence.every(item => item.sessionId === session.session_id));
  }
  for (const observation of result.chain.crypto_observations.filter(item => item.session_id === session.session_id)) {
    const entry = [...data.cryptoEntries, ...data.certificateEntries].find(item => item.id === observation.observation_id);
    assert.ok(entry, "Every supported observation, including TLS 1.3 visibility, remains accessible");
    assert.equal(entry.kind, observation.kind);
    assert.equal(entry.value, observation.normalized_value);
    assert.deepEqual(JSON.parse(entry.technicalDetails), observation);
    assert.deepEqual(entry.limitations, observation.limitations);
    assert.deepEqual(entry.evidence.map(item => item.evidenceId), observation.evidence_ids);
  }
  assert.equal(data.cryptoEntries.find(entry => entry.kind === "forward_secrecy").state, "not_assessed", "Version/cipher/key-share do not synthesize Forward Secrecy");
  assert.deepEqual(data.captureLimitations, session.limitations);
}
const tied = structuredClone(result.chain.protocol_events.slice(0, 3));
tied[0].sequence_index = 5;
tied[1].sequence_index = 1;
tied[2].sequence_index = 1;
tied[1].timestamp = "2026-09-12T00:00:05Z";
tied[2].timestamp = "2026-09-12T00:00:01Z";
const tiedBefore = JSON.stringify(tied);
assert.deepEqual(orderProtocolEvents(tied).map(event => event.event_id), [tied[1].event_id, tied[2].event_id, tied[0].event_id], "Sequence and original occurrence take precedence over timestamps");
assert.equal(JSON.stringify(tied), tiedBefore);

const noRecords = structuredClone(result);
noRecords.chain.anomaly_results = [];
noRecords.chain.protocol_events = [];
noRecords.chain.crypto_observations = [];
noRecords.chain.derived_facts = [];
noRecords.chain.findings = [];
noRecords.chain.rule_evaluations = [];
noRecords.chain.policy_risk = null;
const emptyXray = buildSessionXRayData(analysisResultSchema.parse(noRecords), result.chain.sessions[0].session_id);
assert.equal(emptyXray.events.length, 0, "Reference milestones must never become event records");
assert.equal(emptyXray.negotiationEvents.length, 0);
assert.equal(emptyXray.certificateEntries.length, 0);
assert.equal(emptyXray.tls13CertificateUnavailable, false, "Missing data does not imply a TLS 1.3 visibility cause");
assert.equal(emptyXray.cryptoEntries.find(entry => entry.kind === "tls_upgrade_completed").state, "not_assessed");

const genericCapability = structuredClone(result);
const capability = genericCapability.chain.protocol_events.find(event => event.event_type === "capability_advertised");
capability.state_before = "ready";
capability.state_after = "ready";
const genericData = buildSessionXRayData(analysisResultSchema.parse(genericCapability), capability.session_id);
assert.ok(!genericData.negotiationEvents.some(event => event.eventId === capability.event_id), "Generic capability is not a TLS offer without a source state");
assert.ok(genericData.events.some(event => event.eventId === capability.event_id));

for (const [kind, value, normalized_value, observability] of [
  ["supported_versions", ["TLS_1_2", "TLS_1_3"], "TLS_1_2, TLS_1_3", "observed"],
  ["certificate_subject", "CN=example.test", "CN=example.test", "observed"],
  ["certificate_trusted_path_validated", "unknown", "unknown", "derived"],
  ["certificate_service_identity_validated", "not_assessed", "not_assessed", "not_observable"],
  ["certificate_revocation_checked", "not_applicable", "not_applicable", "not_applicable"],
]) {
  const variant = structuredClone(result);
  const observation = variant.chain.crypto_observations.find(item => item.kind === "key_share_group");
  Object.assign(observation, { kind, value, normalized_value, observability });
  const data = buildSessionXRayData(analysisResultSchema.parse(variant), observation.session_id);
  const entry = [...data.cryptoEntries, ...data.certificateEntries].find(item => item.id === observation.observation_id);
  assert.equal(entry.kind, kind);
  assert.equal(entry.value, normalized_value, "Unavailable result values remain independent of provenance");
  assert.deepEqual(JSON.parse(entry.technicalDetails), observation);
  assert.deepEqual(entry.evidence.map(item => item.evidenceId), observation.evidence_ids);
  assert.equal(data.cryptoEntries.find(item => item.kind === "forward_secrecy").state, "not_assessed");
}
assert.equal(JSON.stringify(result), before);
console.log("PASS: event status/observability, sequence ties, event/frame/evidence/session identity, no synthetic milestones, capability versus TLS offer, raw/normalized crypto and limitations, unavailable states, no inferred Forward Secrecy or certificate trust.");
