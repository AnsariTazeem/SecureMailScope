// Pure projections and actual React markup; not browser measurement proof.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import Module, { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
const load = createRequire(import.meta.url);
const ts = load('typescript');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src');
const originalResolve = Module._resolveFilename;
Module._resolveFilename = function(request, ...args) {
  return originalResolve.call(this, request.startsWith('@/') ? path.join(root, request.slice(2)) : request, ...args);
};
for (const ext of ['.ts', '.tsx']) Module._extensions[ext] = (module, filename) => module._compile(ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true }, fileName: filename,
}).outputText, filename);
Module._extensions['.css'] = () => {};
const source = file => load(path.join(root, file));
const { loadPrototypeAnalysisDataset } = source('mocks/load-prototype-dataset.ts');
const { buildProofMapData } = source('components/analysis/proof-map/proof-map-view-model.ts');
const { buildFindingInvestigation, investigationVisibility, ProofMapInvestigationError } = source('components/analysis/proof-map/proof-map-investigation.ts');
const { suppliedValue, eventState, factTitle, proofGeometry } = source('components/analysis/proof-map/proof-map-presentation.ts');
const { ProofMapGraph, ProofNodeCard, NodeInspector, layoutNodes } = source('components/analysis/proof-map/proof-map-graph.tsx');
const { createElement: h } = load('react');
const { renderToStaticMarkup } = load('react-dom/server');
const { ReactFlowProvider } = load('@xyflow/react');
const demo = loadPrototypeAnalysisDataset();
const before = JSON.stringify(demo);
const graph = buildProofMapData(demo);
const graphMarkup = renderToStaticMarkup(h(ProofMapGraph, {data: graph}));
for (const unreachable of ['unknown', 'not_present', 'not_assessed']) {
  assert.ok(!graphMarkup.includes(`option value="${unreachable}"`));
}
assert.ok(graphMarkup.includes('option value="session_secrets_required"'));
assert.equal(graph.graphNodes.length, 45);
assert.equal(graph.graphEdges.length, 57);
assert.equal(graph.relationshipCount, 61);
assert.equal(new Set(graph.graphNodes.map(n => n.id)).size, 45);

const findingId = 'fnd_475510c505d60661';
const findingSessionId = 'ses_3ac703c890cdeada';
const investigation = buildFindingInvestigation(
  graph.graphNodes,
  graph.sessions.flatMap(session => session.relationships),
  findingId,
);
const expectedSupportNodes = [
  findingId,
  'fact_9da556d717b4ce0f',
  'fact_06514e50f05f65bb',
  'fact_3ee3c17280709d66',
  'eve_cda138a2da129299',
  'eve_30bb7b2a593a0b92',
  'obs_e71da20b2b227144',
  'ev_19f8674446ca345e',
  'ev_80b0cc666ae116ef',
].sort();
const expectedSupportEdges = [
  `finding.fact_ids:fact_9da556d717b4ce0f:${findingId}`,
  `finding.fact_ids:fact_06514e50f05f65bb:${findingId}`,
  `finding.fact_ids:fact_3ee3c17280709d66:${findingId}`,
  `finding.evidence_ids:ev_19f8674446ca345e:${findingId}`,
  `finding.evidence_ids:ev_80b0cc666ae116ef:${findingId}`,
  'fact.source_event_ids:eve_cda138a2da129299:fact_9da556d717b4ce0f',
  'fact.source_observation_ids:obs_e71da20b2b227144:fact_06514e50f05f65bb',
  'fact.source_event_ids:eve_30bb7b2a593a0b92:fact_3ee3c17280709d66',
  'event.evidence_ids:ev_19f8674446ca345e:eve_cda138a2da129299',
  'event.evidence_ids:ev_80b0cc666ae116ef:eve_30bb7b2a593a0b92',
].sort();
assert.equal(investigation.sessionId, findingSessionId);
assert.deepEqual([...investigation.nodeIds].sort(), expectedSupportNodes);
assert.deepEqual([...investigation.edgeIds].sort(), expectedSupportEdges);
assert.ok(expectedSupportEdges.every(id => graph.graphEdges.some(edge => edge.relationshipId === id)));
assert.deepEqual(
  investigation.nonCanvasPolicyRelationships.map(edge => edge.relationshipId).sort(),
  [
    `evaluation.generated_finding_id:eval_1a2076fa0c5bf75e:${findingId}`,
    'evaluation.input_fact_ids:fact_06514e50f05f65bb:eval_1a2076fa0c5bf75e',
    'evaluation.input_fact_ids:fact_3ee3c17280709d66:eval_1a2076fa0c5bf75e',
    'evaluation.input_fact_ids:fact_9da556d717b4ce0f:eval_1a2076fa0c5bf75e',
  ].sort(),
);
const unavailableSupport = graph.graphNodes.find(node => node.id === 'obs_e71da20b2b227144');
assert.equal(unavailableSupport.value, 'not_observable');
assert.equal(unavailableSupport.directEvidence.length, 0);
assert.equal(unavailableSupport.throughSourceEvidence.length, 0);
assert.ok(unavailableSupport.limitations.some(limitation => limitation.detail === 'session_continued_in_plaintext'));

const noEvidenceVisibleNodes = new Set(
  graph.graphNodes.filter(node => node.kind !== 'evidence').map(node => node.id),
);
const noEvidenceVisibleEdges = new Set(
  graph.graphEdges
    .filter(edge => noEvidenceVisibleNodes.has(edge.fromId) && noEvidenceVisibleNodes.has(edge.toId))
    .map(edge => edge.relationshipId),
);
const filteredSupport = investigationVisibility(
  investigation,
  noEvidenceVisibleNodes,
  noEvidenceVisibleEdges,
);
assert.equal(filteredSupport.visibleNodeIds.size, 7);
assert.equal(filteredSupport.hiddenNodeCount, 2);
assert.equal(filteredSupport.visibleEdgeIds.size, 6);
assert.equal(filteredSupport.hiddenEdgeCount, 4);
assert.ok([...filteredSupport.visibleEdgeIds].every(id => investigation.edgeIds.has(id)));

const makeNode = (id, kind, sessionId = 'session-a', captureId = 'capture-a') => ({
  id, kind, sessionIds: [sessionId], captureId, title: id, value: id,
  context: [], shortId: id, state: 'observed', stateLabel: 'observed',
  metadata: '', order: 0, inspectorRows: [], directEvidence: [],
  throughSourceEvidence: [], limitations: [], href: null, hrefLabel: null,
});
const makeRelationship = (fromId, fromKind, toId, toKind, contractField, sessionId = 'session-a') => ({
  relationshipId: `${contractField}:${fromId}:${toId}`,
  sessionId, fromId, fromKind, toId, toKind, contractField,
  relationshipType: contractField.startsWith('finding.') ? 'policy' : contractField.endsWith('evidence_ids') ? 'direct_evidence' : 'declared_source',
});
const syntheticNodes = [
  makeNode('finding-a', 'finding'), makeNode('finding-b', 'finding'),
  makeNode('fact-a', 'fact'), makeNode('fact-b', 'fact'),
  makeNode('event-a', 'event'), makeNode('evidence-a', 'evidence'),
];
const syntheticRelationships = [
  makeRelationship('fact-b', 'fact', 'finding-a', 'finding', 'finding.fact_ids'),
  makeRelationship('fact-a', 'fact', 'fact-b', 'fact', 'fact.source_fact_ids'),
  makeRelationship('event-a', 'event', 'fact-a', 'fact', 'fact.source_event_ids'),
  makeRelationship('evidence-a', 'evidence', 'event-a', 'event', 'event.evidence_ids'),
  makeRelationship('fact-a', 'fact', 'finding-b', 'finding', 'finding.fact_ids'),
  makeRelationship('evidence-a', 'evidence', 'finding-b', 'finding', 'finding.evidence_ids'),
];
const syntheticInvestigation = buildFindingInvestigation(syntheticNodes, syntheticRelationships, 'finding-a');
assert.deepEqual(
  [...syntheticInvestigation.nodeIds].sort(),
  ['evidence-a', 'event-a', 'fact-a', 'fact-b', 'finding-a'].sort(),
);
assert.ok(!syntheticInvestigation.nodeIds.has('finding-b'));
assert.ok(!syntheticInvestigation.edgeIds.has('finding.fact_ids:fact-a:finding-b'));
assert.ok(!syntheticInvestigation.edgeIds.has('finding.evidence_ids:evidence-a:finding-b'));

assert.throws(
  () => buildFindingInvestigation(
    syntheticNodes,
    [...syntheticRelationships, makeRelationship('missing-evidence', 'evidence', 'event-a', 'event', 'event.evidence_ids')],
    'finding-a',
  ),
  ProofMapInvestigationError,
);
assert.throws(
  () => buildFindingInvestigation(
    syntheticNodes.map(node => node.id === 'event-a' ? { ...node, sessionIds: ['session-b'] } : node),
    syntheticRelationships,
    'finding-a',
  ),
  ProofMapInvestigationError,
);
assert.throws(
  () => buildFindingInvestigation(
    syntheticNodes.map(node => node.id === 'event-a' ? { ...node, captureId: 'capture-b' } : node),
    syntheticRelationships,
    'finding-a',
  ),
  ProofMapInvestigationError,
);
assert.throws(
  () => buildFindingInvestigation(
    syntheticNodes,
    [
      ...syntheticRelationships,
      makeRelationship('fact-b', 'fact', 'fact-a', 'fact', 'fact.source_fact_ids'),
    ],
    'finding-a',
  ),
  ProofMapInvestigationError,
);
const expectedIds = ['captures','sessions','evidence','protocol_events','crypto_observations','derived_facts','findings'].flatMap((kind, i) => demo.chain[kind].map(r => r[['capture_id','session_id','evidence_id','event_id','observation_id','fact_id','finding_id'][i]]));
assert.deepEqual(graph.graphNodes.map(n=>n.id).sort(), expectedIds.sort());
for (const edge of graph.graphEdges) {
  assert.equal(edge.relationshipId, `${edge.contractField}:${edge.fromId}:${edge.toId}`);
  const fields = {'session.capture_id':['sessions','session_id','capture_id'], 'session.classification_evidence_ids':['sessions','session_id','classification_evidence_ids'], 'event.session_id':['protocol_events','event_id','session_id'], 'event.evidence_ids':['protocol_events','event_id','evidence_ids'], 'observation.session_id':['crypto_observations','observation_id','session_id'], 'observation.evidence_ids':['crypto_observations','observation_id','evidence_ids'], 'fact.source_event_ids':['derived_facts','fact_id','source_event_ids'], 'fact.source_observation_ids':['derived_facts','fact_id','source_observation_ids'], 'fact.source_fact_ids':['derived_facts','fact_id','source_fact_ids'], 'finding.fact_ids':['findings','finding_id','fact_ids'], 'finding.evidence_ids':['findings','finding_id','evidence_ids']};
  const [collection,id,field] = fields[edge.contractField];
  const target = demo.chain[collection].find(r=>r[id]===edge.toId);
  assert.ok(target);
  assert.ok(Array.isArray(target[field]) ? target[field].includes(edge.fromId) : target[field]===edge.fromId);
}
assert.equal(suppliedValue(true), 'Yes (true)');
assert.equal(suppliedValue(false), 'No (false)');
assert.equal(suppliedValue(0), '0');
assert.equal(suppliedValue(null), 'Null — no supplied value');
assert.equal(suppliedValue(''), 'Empty string');
for (const state of ['unknown','not_present','not_assessed','not_observable','not_applicable','session_secrets_required']) assert.equal(suppliedValue(state), state);
assert.equal(factTitle('tls_upgrade_completed'), 'TLS upgrade completion');
assert.equal(factTitle('custom_success'), 'Fact: custom success');
for (const observability of ['observed','derived','policy_inferred','not_observable','incomplete_capture','session_secrets_required','not_applicable']) {
  for (const status of ['observed','inferred','not_observable','incomplete_capture']) {
    const expected = ['not_observable','incomplete_capture'].includes(status) ? status : status==='inferred'&&observability==='observed' ? 'derived' : observability;
    assert.equal(eventState({event_status:status,observability}),expected);
  }
}
const falseNode = graph.graphNodes.find(n=>n.id==='fact_06514e50f05f65bb');
assert.equal(falseNode.value, 'No (false)');
assert.equal(falseNode.stateLabel, 'derived');
assert.equal(graph.graphNodes.find(n=>n.id==='fact_db3c94f144cfba4d').value, 'Yes (true)');
const variant = structuredClone(demo);
variant.chain.derived_facts[0].value = 0;
variant.chain.derived_facts[1].value = '<script>hostile-value</script>'.repeat(40);
variant.chain.derived_facts[0].limitations = [{code:'not_present',summary:'Same summary',detail:'detail-one'},{code:'not_present',summary:'Same summary',detail:'detail-two'}];
variant.chain.crypto_observations[0].value = null;
variant.chain.protocol_events[0].event_status = 'inferred';
variant.chain.evidence[0].normalized_value = 'UNSAFE_EVIDENCE_MARKER';
variant.chain.findings[0].title = '<img src=x onerror=alert(1)>'.repeat(8);
variant.chain.findings[0].rationale = '<script>alert(1)</script>';
const projected = buildProofMapData(variant);
assert.equal(projected.graphNodes.find(n=>n.id===variant.chain.derived_facts[0].fact_id).value,'0');
assert.equal(projected.graphNodes.find(n=>n.id===variant.chain.crypto_observations[0].observation_id).value,'Null — no supplied value');
assert.equal(projected.graphNodes.find(n=>n.id===variant.chain.protocol_events[0].event_id).stateLabel,'derived');
for (const node of projected.graphNodes) {
  const card = renderToStaticMarkup(h(ReactFlowProvider, null, h(ProofNodeCard, {data:{...node, highlighted:false,dimmed:false,onInspect:()=>{}}})));
  const inspector = renderToStaticMarkup(h(NodeInspector, {node,nodes:projected.graphNodes,relationships:projected.graphEdges}));
  assert.ok(!card.includes('UNSAFE_EVIDENCE_MARKER') && !inspector.includes('UNSAFE_EVIDENCE_MARKER'));
  assert.ok(!card.includes('<img') && !inspector.includes('<script>'));
  assert.ok(inspector.includes('Technical details'));
  for (const limitation of node.limitations) {
    assert.ok(inspector.includes(limitation.detail));
    assert.ok(inspector.includes(limitation.scope));
  }
  const selectedCard = renderToStaticMarkup(h(ReactFlowProvider, null, h(ProofNodeCard, {data:{...node, highlighted:true,dimmed:false,onInspect:()=>{}}})));
  assert.equal(card.match(/style="[^"]*"/)[0], selectedCard.match(/style="[^"]*"/)[0]);
}
const sessions = graph.sessions.map(s=>s.sessionId).sort();
const positioned = layoutNodes(graph.graphNodes, sessions);
assert.deepEqual(positioned.map(n=>n.id), graph.graphNodes.map(n=>n.id));
for (const a of positioned) for (const b of positioned) {
  if (a.id!==b.id && a.position.x===b.position.x) assert.ok(Math.abs(a.position.y-b.position.y)>=proofGeometry.height);
}
assert.equal(JSON.stringify(demo),before);
console.log('PASS: supplied values, qualified events, exact owned limitations, escaped React markup, safe evidence previews, unchanged declared identities/topology, exact finding support, visibility counts, fail-closed traversal, fixed selected-card geometry and non-overlapping lanes.');
