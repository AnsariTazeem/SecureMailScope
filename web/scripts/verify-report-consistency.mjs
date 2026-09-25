// Source/render/download verification; neither browser nor live backend proof.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
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
for (const extension of [".ts", ".tsx"]) {
  Module._extensions[extension] = (module, filename) => module._compile(ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true, resolveJsonModule: true }, fileName: filename,
  }).outputText, filename);
}
// CSS rendering and pagination remain pending browser checks.
Module._extensions[".css"] = (module) => { module.exports = { report: "report" }; };
const { createElement } = load("react");
const { renderToStaticMarkup } = load("react-dom/server");
const source = (file) => load(path.join(root, file));
const { loadPrototypeAnalysisDataset, PROTOTYPE_ANALYSIS_ID } = source("mocks/load-prototype-dataset.ts");
const { buildReportPageData } = source("components/analysis/report/report-view-model.ts");
const { ReportWorkspace } = source("components/analysis/report/report-workspace.tsx");
const { ReportExportActions } = source("components/analysis/report/report-export-actions.tsx");
const { validateFindingsIntegrity } = source("components/analysis/findings/findings-integrity.ts");
const { buildPolicyFindingsData } = source("components/analysis/findings/findings-view-model.ts");
const { selectRecommendations } = source("components/analysis/recommendations/recommendations-view-model.ts");
const { buildSessionsExplorerData } = source("components/analysis/sessions/session-view-model.ts");
const { getAnalysisDataSourceForId } = source("lib/api/client.ts");
const { analysisResultSchema, DATASET_LABEL } = source("lib/contracts/analysis.ts");
const { createDemoChainDownload, fetchRealChainDownload, fetchFindingArtifactDownload } = source("lib/api/export-downloads.ts");
const output = fs.mkdtempSync(path.join(os.tmpdir(), "sms-report-review-"));
const demo = loadPrototypeAnalysisDataset();
const before = JSON.stringify(demo);
const escape = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#x27;");
const render = (result) => renderToStaticMarkup(createElement(ReportWorkspace, { data: buildReportPageData(result), demoChain: result.data_source === "mock" ? result.chain : null })).replaceAll(/<!--.*?-->/g, "");
// Interpret only explicit report visibility markers, not browser layout/CSS.
// This lets content checks catch raw records leaking ahead of the appendix.
function reportMarkupFor(html, mode) {
  const stack = [];
  const voidTags = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);
  let output = "";
  for (const token of html.match(/<[^>]*>|[^<]+/g) ?? []) {
    if (token.startsWith("</")) {
      const hidden = stack.pop();
      if (!hidden) output += token;
    } else if (token.startsWith("<")) {
      const tag = token.match(/^<([a-zA-Z0-9-]+)/)?.[1];
      if (!tag) continue;
      const hidden = Boolean(stack.at(-1)) || (mode === "print"
        ? / data-report-screen-only=| data-print-hide=/.test(token)
        : / data-report-print-only=/.test(token));
      if (!hidden) output += token;
      if (!voidTags.has(tag) && !token.endsWith("/>")) stack.push(hidden);
    } else if (!stack.at(-1)) output += token;
  }
  assert.equal(stack.length, 0, "Balanced rendered markup required by the content projection");
  return output;
}
function verifyPrintContent(result, html) {
  const printed = reportMarkupFor(html, "print");
  const screen = reportMarkupFor(html, "screen");
  const appendixStart = printed.lastIndexOf("<section", printed.indexOf("data-report-appendix="));
  assert.ok(appendixStart > 0);
  const main = printed.slice(0, appendixStart);
  const appendix = printed.slice(appendixStart);
  assert.ok(!main.includes("<pre"), "Raw JSON must never interrupt the printed narrative");
  assert.ok(!printed.includes("<details"), "Print must not depend on disclosure state");
  assert.ok(screen.includes("<details") && !screen.includes("data-report-appendix"), "Keep existing screen disclosures without a duplicate appendix");
  assert.ok(main.indexOf('id="report-assessments"') < main.indexOf('id="report-findings"'));
  assert.ok(main.indexOf('id="report-findings"') < main.indexOf('id="report-recommendations"'));
  assert.ok(main.indexOf('id="report-recommendations"') < main.indexOf('id="report-evidence"'));
  assert.ok(main.includes(escape(result.dataset_label ?? "Production analysis result")));
  const { chain } = result;
  const screenRecords = [chain.analysis, chain.execution, ...chain.captures, ...chain.sessions,
    ...(chain.policy_risk ? [chain.policy_risk] : []), ...chain.anomaly_results,
    ...chain.findings, ...chain.recommendations, ...chain.evidence,
    ...chain.crypto_observations, ...chain.derived_facts,
    chain.protocol_events, chain.rule_evaluations, chain.artifacts];
  for (const record of screenRecords) assert.ok(screen.includes(escape(JSON.stringify(record, null, 2))), "Original source disclosures remain available on screen");
  const records = [chain.analysis, chain.execution, ...chain.captures, ...chain.sessions,
    ...(chain.policy_risk ? [chain.policy_risk] : []), ...chain.anomaly_results,
    ...chain.findings, ...chain.recommendations, ...chain.evidence, ...chain.protocol_events,
    ...chain.crypto_observations, ...chain.derived_facts, ...chain.rule_evaluations, ...chain.artifacts];
  const renderedRecords = [...appendix.matchAll(/<pre[^>]*>([\s\S]*?)<\/pre>/g)].map(match => match[1]);
  assert.equal(renderedRecords.length, records.length, "Each complete record prints once");
  for (const record of records) {
    assert.equal(renderedRecords.filter(text => text === escape(JSON.stringify(record, null, 2))).length, 1, "No missing, altered or repeated complete source record");
  }
  for (const limitation of buildReportPageData(result).limitations) {
    assert.ok(appendix.includes(`data-report-limitation-owner="${escape(limitation.owner)}"`));
    assert.ok(appendix.includes(escape(limitation.summary)));
    if (limitation.detail) assert.ok(appendix.includes(escape(JSON.stringify(limitation.detail).slice(1, -1))));
  }
  for (const limitation of chain.analysis.limitations) assert.ok(main.includes(escape(limitation.summary)));
  for (const session of chain.sessions) for (const limitation of session.limitations) assert.ok(main.includes(escape(limitation.summary)));
  for (const capture of chain.captures) for (const warning of capture.capture_warnings) assert.ok(main.includes(escape(warning)));
  for (const finding of chain.findings) {
    assert.ok(main.includes(`id="${finding.finding_id}"`));
    for (const limitation of finding.limitations) assert.ok(main.includes(escape(limitation.summary)));
  }
  for (const recommendation of chain.recommendations) {
    for (const step of [...recommendation.action_steps, ...recommendation.verification_steps]) assert.ok(main.includes(escape(step)));
  }
  for (const evidence of chain.evidence) assert.ok(main.includes(`id="${evidence.evidence_id}"`));
  for (const [, anchor] of printed.matchAll(/href="#([^"]+)"/g)) assert.ok(printed.includes(`id="${anchor}"`));
  return printed;
}

function verifyContent(result) {
  const data = buildReportPageData(result);
  const html = render(result);
  assert.deepEqual(data.chain, result.chain);
  const policy = buildPolicyFindingsData(result);
  const recommendations = selectRecommendations(policy, null);
  assert.deepEqual(data.recommendations.map(item => item.source.recommendation_id), recommendations.groups.map(item => item.recommendation.recommendationId));
  assert.equal(data.sessions.length, buildSessionsExplorerData(result).rows.length);
  assert.equal(data.chain.policy_risk?.capped_score, policy.policyRisk?.cappedScore);
  for (const [index, item] of data.recommendations.entries()) {
    assert.deepEqual(item.source.action_steps, recommendations.groups[index].recommendation.actionSteps);
    assert.deepEqual(item.source.verification_steps, recommendations.groups[index].recommendation.verificationSteps);
    assert.deepEqual(item.sessions.map(session => session.session_id).sort(), recommendations.groups[index].linkedSessions.map(session => session.sessionId).sort());
    for (const step of [...item.source.action_steps, ...item.source.verification_steps]) assert.ok(html.includes(escape(step)));
  }
  for (const finding of result.chain.findings) {
    assert.ok(html.includes(`id="${finding.finding_id}"`), "Every finding must have a report entry, including beyond five");
    assert.ok(html.includes(escape(finding.rationale)) && html.includes(escape(finding.impact)));
  }
  for (const limitation of data.limitations) {
    assert.ok(html.includes(escape(limitation.owner)) && html.includes(escape(limitation.summary)));
    if (limitation.detail) assert.ok(html.includes(escape(limitation.detail)));
  }
  for (const observation of result.chain.crypto_observations) assert.ok(html.includes(escape(observation.normalized_value)));
  for (const evidence of result.chain.evidence) assert.ok(html.includes(`id="${evidence.evidence_id}"`));
  for (const collection of [result.chain.captures, result.chain.sessions, result.chain.findings, result.chain.recommendations, result.chain.evidence, result.chain.crypto_observations, result.chain.derived_facts, result.chain.anomaly_results]) {
    for (const record of collection) assert.ok(html.includes(escape(JSON.stringify(record, null, 2))), "Every complete technical record must remain escaped and available to screen/print");
  }
  for (const [, anchor] of html.matchAll(/href="#([^"]+)"/g)) assert.ok(html.includes(`id="${anchor}"`), `Missing destination ${anchor}`);
  verifyPrintContent(result, html);
  if (result.chain.analysis.ml_engine_status === "not_run") {
    assert.ok(html.includes("Not run") && html.includes("No anomaly score or ML conclusion is available."));
    assert.ok(!html.includes("Normalized score:"));
  }
  return html;
}
validateFindingsIntegrity(demo);
const demoHtml = verifyContent(demo);
fs.writeFileSync(path.join(output, "demo-report.html"), demoHtml);
fs.writeFileSync(path.join(output, "demo-print-content.html"), verifyPrintContent(demo, demoHtml));
const demoDownload = createDemoChainDownload(PROTOTYPE_ANALYSIS_ID, demo.chain);
const json = await demoDownload.blob.text();
const decoded = JSON.parse(json);
assert.deepEqual(decoded, demo.chain);
assert.ok(decoded.analysis.limitations.some(item => item.summary.includes(DATASET_LABEL)), "Preserve the existing in-document prototype notice without changing the Chain JSON shape");
assert.equal(demoDownload.filename, `${PROTOTYPE_ANALYSIS_ID}.chain.json`);
fs.writeFileSync(path.join(output, demoDownload.filename), json);
assert.throws(() => createDemoChainDownload("ana_ffffffffffffffff", demo.chain));
const unavailable = renderToStaticMarkup(createElement(ReportExportActions, { analysisId: PROTOTYPE_ANALYSIS_ID, dataSource: "mock", demoChain: null }));
assert.ok(unavailable.includes("disabled=") && unavailable.includes("source Chain is missing"));
assert.ok(!render(demo).includes("Download finding PDF"));

// In-memory source variants only; never rewrite fixture evidence.
const rich = structuredClone(demo);
const originalFinding = rich.chain.findings[0];
const originalEvaluation = rich.chain.rule_evaluations.find(item => item.evaluation_id === originalFinding.rule_evaluation_id);
const originalContribution = rich.chain.policy_risk.contributions[0];
for (let index = 1; index <= 6; index++) {
  const suffix = index.toString(16).padStart(16, "0");
  const id = (value) => value.replace(/[0-9a-f]{16}$/, suffix);
  const finding = { ...structuredClone(originalFinding), finding_id: id(originalFinding.finding_id), rule_evaluation_id: id(originalFinding.rule_evaluation_id), title: `Extra supplied finding ${index}` };
  rich.chain.findings.push(finding);
  rich.chain.rule_evaluations.push({ ...structuredClone(originalEvaluation), evaluation_id: finding.rule_evaluation_id, generated_finding_id: finding.finding_id });
  rich.chain.policy_risk.contributions.push({ ...structuredClone(originalContribution), contribution_id: id(originalContribution.contribution_id), finding_id: finding.finding_id });
  rich.chain.recommendations[0].affected_finding_ids.push(finding.finding_id);
}
rich.chain.recommendations.push({ ...structuredClone(rich.chain.recommendations[0]), recommendation_id: "REC-REPORT-UNLINKED", affected_finding_ids: [], title: "Unlinked supplied action", action_steps: ["Keep exact step", "Keep exact step"], verification_steps: [] });
const limitation = rich.chain.analysis.limitations[0];
for (const [index, owner] of [rich.chain.analysis, rich.chain.sessions[0], rich.chain.protocol_events[0], rich.chain.crypto_observations[0], rich.chain.derived_facts[0], rich.chain.findings[0], rich.chain.policy_risk].entries()) owner.limitations.push({ ...limitation, summary: "Same summary", detail: `Distinct detail ${index}` });
const malicious = '<script>alert("report")</script><img src=x onerror=alert(1)> & exact';
rich.chain.recommendations[0].action_steps.push(malicious);
rich.chain.crypto_observations[0].normalized_value = malicious;
rich.chain.analysis.analysis_status = "partial";
rich.chain.captures[0].capture_warnings.push("Exact warning <capture gap>");
analysisResultSchema.parse(rich);
validateFindingsIntegrity(rich);
const richHtml = verifyContent(rich);
assert.equal(buildReportPageData(rich).limitations.filter(item => item.summary === "Same summary").length, 7);
assert.ok(richHtml.includes("Unlinked supplied action") && richHtml.includes("No finding relationship supplied"));
assert.ok(richHtml.includes(escape(malicious)) && !richHtml.includes(malicious));
fs.writeFileSync(path.join(output, "partial-report.html"), richHtml);
fs.writeFileSync(path.join(output, "larger-print-content.html"), verifyPrintContent(rich, richHtml));
const longRecord = structuredClone(rich);
longRecord.chain.evidence[0].safe_excerpt = "Long source value with <markup> & exact spacing.\n".repeat(250);
longRecord.chain.findings[0].limitations.push({ ...limitation, summary: "Long finding uncertainty", detail: "Detail with exact newlines\n".repeat(200) });
const longHtml = verifyContent(longRecord);
fs.writeFileSync(path.join(output, "long-record-print-content.html"), verifyPrintContent(longRecord, longHtml));
const empty = structuredClone(demo);
Object.assign(empty.chain, { sessions: [], evidence: [], protocol_events: [], crypto_observations: [], derived_facts: [], rule_evaluations: [], findings: [], policy_risk: null, recommendations: [], anomaly_results: [] });
empty.chain.analysis.rule_engine_status = "not_run";
validateFindingsIntegrity(empty);
assert.ok(verifyContent(empty).includes("No policy score was supplied."));
const real = structuredClone(demo);
Object.assign(real, { data_source: "api", dataset_kind: "production_analysis_result", dataset_label: null });
const realHtml = verifyContent(real);
assert.ok(realHtml.includes("Download finding PDF") && realHtml.includes("Download finding HTML"));
assert.ok(!realHtml.includes("Download demo Chain JSON")); // Source limitation text remains exact even in this simulated API envelope.
fs.writeFileSync(path.join(output, "api-path-simulated-report.html"), realHtml);

for (const state of ["unknown", "not_observable", "not_assessed", "not_applicable"]) {
  const variant = structuredClone(demo);
  variant.chain.crypto_observations[0].normalized_value = state;
  variant.chain.derived_facts[0].value = state;
  verifyContent(variant);
}
const zero = structuredClone(demo);
zero.chain.policy_risk.capped_score = 0;
assert.ok(verifyContent(zero).includes("0 / 100"), "A supplied policy zero stays distinct from unavailable ML");
const invalid = structuredClone(demo);
invalid.chain.findings[0].session_id = "ses_ffffffffffffffff";
assert.throws(() => validateFindingsIntegrity(invalid), /unresolved|session/i);
const originalFetch = globalThis.fetch;
const calls = [];
const respond = (body, options) => { globalThis.fetch = async (url, init) => { calls.push([url, init]); return new Response(body, options); }; };
try {
  globalThis.fetch = async () => { throw new Error("Demo must not fetch"); };
  assert.deepEqual(await getAnalysisDataSourceForId(PROTOTYPE_ANALYSIS_ID).getResult(PROTOTYPE_ANALYSIS_ID), demo);
  const realId = "ana_ffffffffffffffff";
  const apiChain = structuredClone(demo.chain);
  apiChain.analysis.analysis_id = realId;
  for (const finding of apiChain.findings) finding.analysis_id = realId;
  apiChain.policy_risk.analysis_id = realId;
  for (const artifact of apiChain.artifacts) artifact.analysis_id = realId;
  const summary = {
    api_version: "v1", chain_schema_version: apiChain.chain_schema_version,
    analysis_id: realId, analyzer_version: apiChain.analysis.analyzer_version,
    analysis_status: apiChain.analysis.analysis_status,
    rule_engine_status: apiChain.analysis.rule_engine_status,
    ml_engine_status: apiChain.analysis.ml_engine_status,
    capture_ids: apiChain.captures.map(item => item.capture_id).sort(),
    session_ids: apiChain.sessions.map(item => item.session_id).sort(),
    finding_ids: apiChain.findings.map(item => item.finding_id).sort(),
    capture_count: apiChain.captures.length, session_count: apiChain.sessions.length,
    evidence_count: apiChain.evidence.length, protocol_event_count: apiChain.protocol_events.length,
    derived_fact_count: apiChain.derived_facts.length, rule_evaluation_count: apiChain.rule_evaluations.length,
    finding_count: apiChain.findings.length, recommendation_count: apiChain.recommendations.length,
    policy_risk: { policy_risk_id: apiChain.policy_risk.policy_risk_id, profile_id: apiChain.policy_risk.profile_id, uncapped_score: apiChain.policy_risk.uncapped_score, capped_score: apiChain.policy_risk.capped_score, available: true },
    limitations: apiChain.analysis.limitations,
  };
  globalThis.fetch = async (url) => new Response(JSON.stringify(url.endsWith("/chain") ? apiChain : summary), { headers: { "content-type": "application/json" } });
  const apiResult = await getAnalysisDataSourceForId(realId).getResult(realId);
  assert.equal(apiResult.data_source, "api");
  assert.equal(apiResult.dataset_label, null);
  validateFindingsIntegrity(apiResult);
  fs.writeFileSync(path.join(output, "api-adapter-mocked-report.html"), verifyContent(apiResult));
  summary.session_count++;
  await assert.rejects(getAnalysisDataSourceForId(realId).getResult(realId), /inconsistent/);
  const bytes = `  ${JSON.stringify(demo.chain)}\n\n`;
  respond(bytes, { headers: { "content-type": "application/json", "content-disposition": 'attachment; filename="original.json"' } });
  const downloaded = await fetchRealChainDownload(PROTOTYPE_ANALYSIS_ID);
  assert.equal(await downloaded.blob.text(), bytes, "Backend Chain bytes must not be reserialized");
  assert.equal(downloaded.filename, "original.json");
  assert.ok(calls.at(-1)[0].endsWith(`/api/v1/analyses/${PROTOTYPE_ANALYSIS_ID}/chain`));
  assert.equal(calls.at(-1)[1].cache, "no-store");
  assert.ok(calls.at(-1)[1].signal instanceof AbortSignal);
  const findingId = demo.chain.findings[0].finding_id;
  for (const [format, type, body] of [["html", "text/html", "<!doctype html><p>Original backend fixture response</p>"], ["pdf", "application/pdf", "%PDF-1.7\nMock signature only; not a rendered PDF"]]) {
    respond(body, { headers: { "content-type": type, "content-disposition": `attachment; filename="../../unsafe.${format}"` } });
    const file = await fetchFindingArtifactDownload(PROTOTYPE_ANALYSIS_ID, findingId, format);
    assert.equal(await file.blob.text(), body);
    assert.equal(file.filename, `${findingId}.finding.${format}`);
    assert.ok(calls.at(-1)[0].endsWith(`/findings/${findingId}/artifacts/${format}`));
  }
  for (const status of [404, 413, 500, 503]) {
    respond("unavailable", { status });
    await assert.rejects(fetchRealChainDownload(PROTOTYPE_ANALYSIS_ID));
    await assert.rejects(fetchFindingArtifactDownload(PROTOTYPE_ANALYSIS_ID, findingId, "html"));
  }
  for (const [body, type] of [["", "application/json"], ["bad json", "application/json"], [bytes, "text/html"], [JSON.stringify({ ...demo.chain, analysis: { ...demo.chain.analysis, analysis_id: "ana_ffffffffffffffff" } }), "application/json"]]) {
    respond(body, { headers: { "content-type": type } });
    await assert.rejects(fetchRealChainDownload(PROTOTYPE_ANALYSIS_ID));
  }
  respond("not a PDF", { headers: { "content-type": "application/pdf" } });
  await assert.rejects(fetchFindingArtifactDownload(PROTOTYPE_ANALYSIS_ID, findingId, "pdf"));
  respond("", { headers: { "content-type": "text/html" } });
  await assert.rejects(fetchFindingArtifactDownload(PROTOTYPE_ANALYSIS_ID, findingId, "html"));
  globalThis.fetch = async () => { throw new DOMException("Timeout", "TimeoutError"); };
  await assert.rejects(fetchRealChainDownload(PROTOTYPE_ANALYSIS_ID), /timed out/);
  globalThis.fetch = async () => { throw new TypeError("Network unavailable"); };
  await assert.rejects(fetchRealChainDownload(PROTOTYPE_ANALYSIS_ID), /backend is unavailable/);
} finally { globalThis.fetch = originalFetch; }
assert.equal(JSON.stringify(demo), before);
console.log(`PASS: narrative-before-appendix print structure, every raw record exactly once, long-record/source retention, screen disclosures preserved; report source/render parity, complete findings/recommendations, scoped anchors, distinct limitations, escaped source strings, labelled demo JSON, unchanged mocked backend bytes and download failures. Inspection files: ${output}`);
