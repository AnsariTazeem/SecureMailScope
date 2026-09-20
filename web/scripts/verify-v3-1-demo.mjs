// Source/projection/render checks; browser acceptance is separate.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import Module, { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
const require = createRequire(import.meta.url), ts = require('typescript');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src');
const resolve = Module._resolveFilename;
Module._resolveFilename = function(request, ...args) { return resolve.call(this, request.startsWith('@/') ? path.join(root, request.slice(2)) : request, ...args); };
for (const ext of ['.ts', '.tsx']) Module._extensions[ext] = (module, file) => module._compile(ts.transpileModule(fs.readFileSync(file, 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true }, fileName: file,
}).outputText, file);
Module._extensions['.css'] = module => { module.exports = {}; };
const source = file => require(path.join(root, file));
const { createElement: h } = require('react'), { renderToStaticMarkup: render } = require('react-dom/server');
const { loadPrototypeAnalysisDataset, PROTOTYPE_ANALYSIS_ID } = source('mocks/load-prototype-dataset.ts');
const { analysisResultSchema } = source('lib/contracts/analysis.ts');
const { validateFindingsIntegrity } = source('components/analysis/findings/findings-integrity.ts');
const { buildAnomalyFindingsData } = source('components/analysis/findings/findings-view-model.ts');
const { buildSessionXRayData } = source('components/analysis/session-xray/session-xray-view-model.ts');
const { buildProofMapData } = source('components/analysis/proof-map/proof-map-view-model.ts');
const { buildReportPageData } = source('components/analysis/report/report-view-model.ts');
const { ReportWorkspace } = source('components/analysis/report/report-workspace.tsx');
const { MLAnomalyExplorer } = source('components/analysis/findings/ml-anomaly-explorer.tsx');
const { MLInvestigationGuidance } = source('components/analysis/recommendations/ml-investigation-guidance.tsx');
const { createDemoChainDownload } = source('lib/api/export-downloads.ts');
const sample = loadPrototypeAnalysisDataset(), before = JSON.stringify(sample), chain = sample.chain;
validateFindingsIntegrity(sample);
assert.equal(chain.analysis.ml_engine_status, 'complete');
assert.equal(chain.execution.stage_diagnostics.find(stage => stage.stage === 'anomaly_scoring').status, 'complete');
assert.ok(!before.includes('ml_engine_not_run'));
assert.equal(chain.anomaly_results.length, 2);
const data = buildAnomalyFindingsData(sample);
const findingsHtml = render(h(MLAnomalyExplorer, { data }));
const guidanceHtml = render(h(MLInvestigationGuidance, { data, sessionId: null }));
const reportHtml = render(h(ReportWorkspace, { data: buildReportPageData(sample), demoChain: chain }));
const graph = buildProofMapData(sample);
for (const anomaly of chain.anomaly_results) {
  assert.ok(Object.keys(anomaly.feature_snapshot).length >= 5);
  assert.equal(anomaly.model_id, chain.analysis.model_id);
  assert.equal(anomaly.model_version, chain.analysis.model_version);
  assert.equal(anomaly.interpretation_note, 'Anomalous behavior is not proof of malicious activity.');
  const session = chain.sessions.find(item => item.session_id === anomaly.session_id);
  assert.ok(session);
  for (const field of ['packet_count', 'byte_count']) assert.equal(anomaly.feature_snapshot[field], session[field]);
  assert.equal(anomaly.feature_snapshot.session_duration_seconds, (Date.parse(session.ended_at) - Date.parse(session.started_at)) / 1000);
  assert.ok(buildSessionXRayData(sample, session.session_id).anomalies.some(item => item.anomalyResultId === anomaly.anomaly_result_id));
  assert.ok(findingsHtml.includes(anomaly.anomaly_result_id));
  assert.ok(reportHtml.includes(anomaly.anomaly_result_id));
  assert.ok(guidanceHtml.includes(`${session.session_id}?tab=findings#ml-anomaly-heading`));
  assert.ok(guidanceHtml.includes(String(anomaly.normalized_score)));
  for (const [field, collection, key] of [['linked_fact_ids', 'derived_facts', 'fact_id'], ['linked_observation_ids', 'crypto_observations', 'observation_id'], ['evidence_ids', 'evidence', 'evidence_id']]) {
    for (const id of anomaly[field]) {
      assert.ok(chain[collection].some(item => item[key] === id && item.session_id === anomaly.session_id));
      assert.ok(graph.sessions.flatMap(item => item.relationships).some(link => link.fromId === id && link.toId === anomaly.anomaly_result_id && link.contractField === `anomaly.${field}`));
    }
    const broken = structuredClone(sample);
    broken.chain.anomaly_results[0][field] = ['missing-record'];
    assert.throws(() => validateFindingsIntegrity(analysisResultSchema.parse(broken)), /unknown|unresolved/i);
  }
}
assert.ok(guidanceHtml.includes('ML investigation guidance'));
assert.ok(guidanceHtml.includes('Validate the unusual indicators before taking action'));
assert.ok(!guidanceHtml.includes(chain.recommendations[0].title));
const invalid = render(h(MLInvestigationGuidance, { data, sessionId: 'ses_ffffffffffffffff' }));
assert.ok(invalid.includes('No validated anomaly results'));
assert.ok(!invalid.includes('linked evidence records'));
assert.deepEqual(JSON.parse(await createDemoChainDownload(PROTOTYPE_ANALYSIS_ID, chain).blob.text()), chain);
assert.equal(JSON.stringify(sample), before);
console.log('PASS: two complete illustrative ML records, feature/session consistency, every ML link and graph ledger relationship, broken-link rejection, Findings/report rendering, X-Ray projection, separate scoped advisory guidance, JSON identity and source immutability.');
