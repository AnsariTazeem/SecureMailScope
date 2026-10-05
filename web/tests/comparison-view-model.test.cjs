/* eslint-disable @typescript-eslint/no-require-imports */
// Run with: node --test tests/comparison-view-model.test.cjs
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


const { buildComparisonPageData } = require("../src/components/analysis/compare/comparison-view-model.ts");
const pair = ["ses_05a2650d13a55335", "ses_3ac703c890cdeada"];
const rows = (data) => new Map(data.categories.flatMap((category) => category.rows).map((row) => [row.key, row]));

test("comparison formats observations and findings while retaining explicit unknown states and evidence", () => {
  const input = validated(fixture);
  const before = JSON.stringify(input);
  const data = buildComparisonPageData(input, ...pair);
  const fields = rows(data);
  assert.equal(fields.get("tls-version").sessionA.value, "TLS 1.3");
  assert.equal(fields.get("tls-version").sessionB.value, "Not observable");
  assert.equal(fields.get("tls-version").sessionB.state, "not_observable");
  assert.equal(fields.get("cipher").sessionA.value, "TLS_AES_128_GCM_SHA256");
  assert.equal(fields.get("forward-secrecy").sessionA.state, "not_assessed");
  assert.equal(fields.get("handshake").sessionA.value, "Yes");
  assert.equal(fields.get("handshake").sessionB.value, "No");
  const finding = input.chain.findings[0];
  assert.equal(fields.get("findings").sessionB.value, finding.title);
  assert.ok(fields.get("findings").sessionB.detail.some((item) => item.includes(finding.finding_id)));
  assert.deepEqual(fields.get("findings").sessionB.evidence.map((item) => item.evidenceId).sort(), [...finding.evidence_ids].sort());
  assert.equal(data.sessionA.sessionId, pair[0]);
  assert.equal(data.sessionB.sessionId, pair[1]);
  assert.equal(data.sessionA.captureSha256, input.chain.captures.find((item) => item.capture_id === data.sessionA.captureId).sha256);
  assert.equal(data.policyRisk.cappedScore, input.chain.policy_risk.capped_score);
  assert.equal(data.mlAnomaly.resultCount, input.chain.anomaly_results.length);
  assert.equal(JSON.stringify(input), before);
});

test("swapping a pair reverses its cells without changing differences; identical sessions have no differences", () => {
  const input = validated(fixture);
  const forward = buildComparisonPageData(input, ...pair);
  const reverse = buildComparisonPageData(input, pair[1], pair[0]);
  assert.equal(forward.differenceCount, reverse.differenceCount);
  const reversed = rows(reverse);
  for (const row of rows(forward).values()) {
    assert.deepEqual(row.sessionA, reversed.get(row.key).sessionB);
    assert.deepEqual(row.sessionB, reversed.get(row.key).sessionA);
    assert.equal(row.differs, reversed.get(row.key).differs);
  }
  const same = buildComparisonPageData(input, pair[0], pair[0]);
  assert.equal(same.differenceCount, 0);
  assert.ok([...rows(same).values()].every((row) => !row.differs));
});

test("absent observations and assessments stay unavailable instead of becoming positive or zero values", () => {
  const input = validated(fixture);
  input.chain.crypto_observations = [];
  input.chain.derived_facts = [];
  input.chain.rule_evaluations = [];
  input.chain.findings = [];
  input.chain.recommendations = [];
  input.chain.policy_risk = null;
  input.chain.anomaly_results = [];
  input.chain.analysis.ml_engine_status = "not_run";
  input.chain.analysis.model_id = null;
  input.chain.analysis.model_version = null;
  const data = buildComparisonPageData(validated(input), ...pair);
  const fields = rows(data);
  assert.equal(fields.get("tls-version").sessionA.state, "not_present");
  assert.equal(fields.get("handshake").sessionA.state, "not_assessed");
  assert.equal(fields.get("forward-secrecy").sessionA.state, "not_assessed");
  assert.equal(fields.get("ml-result").sessionA.state, "not_present");
  assert.equal(data.policyRisk.status, "not_present");
  assert.equal(data.policyRisk.cappedScore, null);
  assert.equal(data.mlAnomaly.engineStatus, "not_run");
  assert.equal(data.mlAnomaly.resultCount, 0);
});

test("V3 presentation hides only the mock source-banner record and retains substantive assessment limitations", () => {
  const input = validated(fixture);
  const data = buildComparisonPageData(input, ...pair);
  const notes = rows(data).get("analysis-limitations").sessionA;
  assert.ok(!notes.detail.some((item) => item.includes("prototype_analysis_dataset")));
  assert.ok(notes.detail.some((item) => item.includes("No trained model was executed")));
  input.data_source = "api";
  input.dataset_kind = "production_analysis_result";
  input.dataset_label = null;
  const production = buildComparisonPageData(validated(input), ...pair);
  assert.ok(rows(production).get("analysis-limitations").sessionA.detail.some((item) => item.includes("prototype_analysis_dataset")));
});
