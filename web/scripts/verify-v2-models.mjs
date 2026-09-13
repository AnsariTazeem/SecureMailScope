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
assert.equal(buildAnomalyFindingsData(result).mlEngineStatus, "not_run");
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
