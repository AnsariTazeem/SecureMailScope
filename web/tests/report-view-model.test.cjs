/* eslint-disable @typescript-eslint/no-require-imports */
// Run with: node --test tests/report-view-model.test.cjs
// Use the existing TypeScript compiler; no additional test dependency is required.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Module = require("node:module");
const { test, after } = require("node:test");
const ts = require("typescript");
const root = path.resolve(__dirname, "..");
const src = path.join(root, "src");
const originalResolve = Module._resolveFilename;
const originalExtensions = { ".ts": Module._extensions[".ts"], ".tsx": Module._extensions[".tsx"] };

Module._resolveFilename = function (request, parent, ...rest) {
  return originalResolve.call(this, request.startsWith("@/") ? path.join(src, request.slice(2)) : request, parent, ...rest);
};
for (const extension of [".ts", ".tsx"]) {
  Module._extensions[extension] = (module, filename) => {
    module.paths = Module._nodeModulePaths(path.dirname(filename));
    module._compile(ts.transpileModule(fs.readFileSync(filename, "utf8"), {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    }).outputText, filename);
  };
}
const { analysisResultSchema } = require("../src/lib/contracts/analysis.ts");
const { validateFindingsIntegrity } = require("../src/components/analysis/findings/findings-integrity.ts");
const { buildReportPageData, reportSessionLabel, groupReportNotes } = require("../src/components/analysis/report/report-view-model.ts");
const fixture = JSON.parse(fs.readFileSync(path.join(src, "mocks/prototype-analysis-dataset.json"), "utf8"));
const validated = (input) => {
  const result = analysisResultSchema.parse(input);
  validateFindingsIntegrity(result);
  return result;
};
after(() => {
  Module._resolveFilename = originalResolve;
  for (const extension of [".ts", ".tsx"]) {
    if (originalExtensions[extension]) Module._extensions[extension] = originalExtensions[extension];
    else delete Module._extensions[extension];
  }
});

test("report preserves source values and action/evidence relationships without mutating the input", () => {
  const input = validated(fixture);
  const before = JSON.stringify(input);
  const report = buildReportPageData(input);
  assert.equal(report.chain, input.chain);
  assert.equal(report.policyRisk.score, input.chain.policy_risk.capped_score);
  assert.equal(report.affectedSessionCount, 1);
  const finding = report.importantFindings[0];
  assert.equal(finding.impact, input.chain.findings[0].impact);
  assert.equal(finding.confidence, input.chain.findings[0].evidence_confidence);
  assert.equal(finding.source, input.chain.findings[0]);
  const recommendation = report.recommendations[0];
  assert.deepEqual(recommendation.affectedFindings.map(item => item.id), recommendation.affectedFindingIds);
  assert.equal(recommendation.affectedSessions[0].id, finding.sessionId);
  assert.deepEqual(recommendation.actionSteps, input.chain.recommendations[0].action_steps);
  assert.deepEqual(recommendation.verificationSteps, input.chain.recommendations[0].verification_steps);
  assert.deepEqual(recommendation.standardsReferences, input.chain.recommendations[0].standards_references);
  assert.equal(JSON.stringify(input), before);
});

test("all findings remain in a large report; repeated sessions are counted once", () => {
  const input = structuredClone(fixture);
  const source = input.chain.findings[0];
  const evaluation = input.chain.rule_evaluations.find(item => item.evaluation_id === source.rule_evaluation_id);
  const contribution = input.chain.policy_risk.contributions[0];
  for (let index = 1; index <= 12; index++) {
    const suffix = index.toString(16).padStart(16, "0");
    const finding = { ...structuredClone(source), finding_id: "fnd_" + suffix, stable_finding_key: "sha256:" + suffix.padStart(64, "0"), rule_evaluation_id: "eval_" + suffix };
    input.chain.findings.push(finding);
    input.chain.rule_evaluations.push({ ...structuredClone(evaluation), evaluation_id: finding.rule_evaluation_id, generated_finding_id: finding.finding_id });
    input.chain.recommendations[0].affected_finding_ids.push(finding.finding_id);
    input.chain.policy_risk.contributions.push({ ...structuredClone(contribution), contribution_id: "plc_" + suffix, finding_id: finding.finding_id });
  }
  const report = buildReportPageData(validated(input));
  assert.equal(report.importantFindings.length, 13);
  assert.equal(report.totalFindings, 13);
  assert.equal(report.affectedSessionCount, 1);
  assert.equal(report.recommendations[0].affectedFindings.length, 13);
  assert.equal(report.recommendations[0].affectedSessions.length, 1);
});

test("equal limitation summaries retain distinct owner records and details", () => {
  const input = structuredClone(fixture);
  const sample = input.chain.analysis.limitations[0] || input.chain.crypto_observations.flatMap(item => item.limitations)[0];
  assert.ok(sample);
  input.chain.analysis.limitations.push({ ...sample, summary: "Same summary", detail: "Analysis detail" });
  input.chain.sessions[0].limitations.push({ ...sample, summary: "Same summary", detail: "Session detail" });
  const report = buildReportPageData(validated(input));
  const records = report.limitations.filter(item => item.summary === "Same summary");
  assert.equal(records.length, 2);
  assert.deepEqual(records.map(item => item.detail), ["Analysis detail", "Session detail"]);
  assert.deepEqual(records.map(item => item.owner), [input.chain.analysis.analysis_id, input.chain.sessions[0].session_id]);
});

test("absent policy/ML outputs stay absent, including a zero-session result", () => {
  const input = structuredClone(fixture);
  for (const field of ["sessions", "evidence", "protocol_events", "crypto_observations", "derived_facts", "rule_evaluations", "findings", "anomaly_results", "recommendations", "artifacts"]) input.chain[field] = [];
  input.chain.policy_risk = null;
  input.chain.analysis.rule_engine_status = "not_run";
  input.chain.analysis.ml_engine_status = "not_run";
  input.chain.analysis.model_id = null;
  input.chain.analysis.model_version = null;
  input.data_source = "api";
  input.dataset_kind = "production_analysis_result";
  input.dataset_label = null;
  const report = buildReportPageData(validated(input));
  assert.equal(report.policyRisk.score, null);
  assert.equal(report.policyRisk.available, false);
  assert.equal(report.mlAnomaly.engineStatus, "not_run");
  assert.equal(report.mlAnomaly.resultCount, 0);
  assert.equal(report.totalSessions, 0);
  assert.deepEqual(report.importantFindings, []);
  assert.deepEqual(report.cryptoDimensions, []);
  assert.equal(report.dataSource, "api");
  assert.equal(report.datasetLabel, null);
});

test("unobservable cryptographic states remain neutral and IPv6 session labels are unambiguous", () => {
  const report = buildReportPageData(validated(fixture));
  const certificate = report.cryptoDimensions.find(dimension => dimension.key === "certificate-observability");
  assert.ok(certificate);
  assert.ok(certificate.values.some(value => value.state === "derived" && value.value === "Certificate not observable · session_secrets_required"));
  assert.equal(report.chain.crypto_observations.find(item => item.kind === "tls13_certificate_unavailable").observability, "session_secrets_required");
  const session = structuredClone(fixture.chain.sessions[0]);
  session.source_endpoint = { ip: "2001:db8::1", port: 2525 };
  assert.match(reportSessionLabel(session), /\[2001:db8::1\]:2525/);
});

test("exact duplicate notes appear once while retaining every owner and differing details", () => {
  const input = [
    { code: "not_assessed", summary: "Same note", detail: "Same detail", owner: "analysis" },
    { code: "not_assessed", summary: "Same note", detail: "Same detail", owner: "stage" },
    { code: "not_assessed", summary: "Same note", detail: "Different detail", owner: "session" },
  ];
  const before = JSON.stringify(input);
  const notes = groupReportNotes(input);
  assert.equal(notes.length, 2);
  assert.deepEqual(notes[0].owners, ["analysis", "stage"]);
  assert.deepEqual(notes[1].owners, ["session"]);
  assert.equal(JSON.stringify(input), before);
});

test("shared ML notes are consolidated without removing source records or session-specific context", () => {
  const report = buildReportPageData(validated(fixture));
  const common = report.anomalyNotes.filter(note => note.summary.includes("Illustrative model scores"));
  assert.equal(common.length, 1);
  assert.equal(common[0].owners.length, 2);
  assert.equal(report.coverageNotes.filter(note => note.summary.includes("Illustrative model scores")).length, 0);
  assert.ok(report.anomalyNotes.some(note => note.summary.includes("No TLS handshake")));
  assert.equal(report.chain.anomaly_results.length, 2);
  assert.equal(report.limitations.filter(note => note.summary.includes("Illustrative model scores")).length, 4);
});

test("additional supplied certificate and legacy-version observations are included without inferring protection", () => {
  const input = structuredClone(fixture);
  const source = input.chain.crypto_observations[0];
  input.chain.crypto_observations.push(
    { ...structuredClone(source), observation_id: "obs_0000000000000031", kind: "certificate_issuer", value: "Test issuer", normalized_value: "Test issuer" },
    { ...structuredClone(source), observation_id: "obs_0000000000000032", kind: "record_layer_legacy_version", value: "TLS_1_2", normalized_value: "TLS_1_2" },
  );
  const report = buildReportPageData(validated(input));
  const issuer = report.additionalCryptoDimensions.find(item => item.key === "observation-certificate_issuer");
  assert.ok(issuer.values.some(item => item.value === "Test issuer" && item.state === source.observability));
  const legacy = report.additionalCryptoDimensions.find(item => item.key === "observation-record_layer_legacy_version");
  assert.match(legacy.description, /not the negotiated TLS version/);
  assert.ok(!report.cryptoDimensions.some(item => item.key === "tls-upgrade-completion"));
  const finding = report.importantFindings[0];
  assert.deepEqual(finding.evidence.map(record => record.evidence_id), report.chain.evidence.filter(record => finding.source.evidence_ids.includes(record.evidence_id)).map(record => record.evidence_id));
});


test("crypto caveats stay with the dimension and the source record used for its values", () => {
  const input = validated(fixture);
  const before = JSON.stringify(input);
  const report = buildReportPageData(input);
  const version = report.cryptoDimensions.find((dimension) => dimension.key === "tls-version");
  const versionObservation = input.chain.crypto_observations.find((observation) => observation.kind === "tls_negotiated_version" && observation.limitations.length);
  assert.ok(versionObservation);
  assert.ok(version.notes.some((note) => note.owners.includes(versionObservation.observation_id) && note.summary === versionObservation.limitations[0].summary));
  const certificate = report.cryptoDimensions.find((dimension) => dimension.key === "certificate-observability");
  const fact = input.chain.derived_facts.find((record) => record.fact_type === "certificate_observability");
  assert.ok(certificate.notes.some((note) => note.owners.includes(fact.fact_id) && note.summary === fact.limitations[0].summary));
  assert.ok(certificate.notes.every((note) => !note.owners.some((owner) => owner.startsWith("obs_"))));
  assert.equal(JSON.stringify(input), before);
});
