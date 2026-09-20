// Static boundaries plus executed source checks; browser acceptance is separate.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import Module, { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const filename = fileURLToPath(import.meta.url);
const root = path.resolve(path.dirname(filename), "../src");
const read = file => fs.readFileSync(path.join(root, file), "utf8");
const load = createRequire(import.meta.url);
const ts = load("typescript");
const compile = (text, file = "test.tsx") => ts.transpileModule(text, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  fileName: file,
}).outputText;

if (!process.argv.includes("--case")) {
  const env = read("lib/config/env.ts");
  assert.match(env, /value === undefined\) return "submission_demo"/);
  assert.ok(!env.includes("http://localhost:8000"));
  const client = read("lib/api/client.ts");
  assert.match(client, /analysisId === PROTOTYPE_ANALYSIS_ID/);
  assert.ok(client.indexOf("throw new SubmissionModeDisabledError") < client.indexOf("new ApiAnalysisDataSource"));
  assert.ok(!client.includes("catch"), "No real-to-demo recovery branch");
  const guard = read("components/analysis/submission-capture-guard.tsx");
  for (const text of [
    "Live capture analysis is unavailable in this evaluation build",
    "Your capture was not uploaded, stored, or analyzed. Live PCAP analysis requires the production analysis service, which is not connected to this submission build. You can explore the curated demo to review the complete investigation workflow.",
    "selectPrototypeDataset()", 'router.push("/analysis/processing")',
  ]) assert.ok(guard.includes(text));
  assert.ok(read("lib/api/errors.ts").includes("Live analysis results are not available in this evaluation build. No demo result was substituted."));
  const layout = read("app/layout.tsx");
  assert.match(layout, /<SubmissionCaptureGuard>/);
  assert.match(layout, /strategy="beforeInteractive"/);
  const capture = read("components/analysis/capture-dropzone.tsx");
  const submission = capture.split("function SubmissionCaptureDropzone()")[1].split("function ConnectedCaptureDropzone")[0];
  for (const forbidden of ["onSelect", "validateCaptureFile", "useDropzone", "FormData", "file.name", "useState"]) assert.ok(!submission.includes(forbidden), forbidden);
  for (const [mode, url, expected] of [
    [undefined, undefined, "demo"], ["submission_demo", "https://example.invalid", "demo"],
    ["submission_demo", "malformed", "demo"], ["invalid", undefined, "invalid"],
    ["", undefined, "invalid"], ["backend_connected", undefined, "invalid"],
    ["backend_connected", "/api", "invalid"], ["backend_connected", "file:///tmp/capture", "invalid"],
    ["backend_connected", "https://example.invalid", "connected"],
  ]) {
    const childEnv = { ...process.env };
    delete childEnv.NEXT_PUBLIC_SECUREMAILSCOPE_MODE;
    delete childEnv.NEXT_PUBLIC_API_BASE_URL;
    if (mode !== undefined) childEnv.NEXT_PUBLIC_SECUREMAILSCOPE_MODE = mode;
    if (url !== undefined) childEnv.NEXT_PUBLIC_API_BASE_URL = url;
    const result = spawnSync(process.execPath, [filename, "--case", expected], { env: childEnv, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  }

  // Execute the actual submission input handlers with no File objects supplied.
  let disclosures = 0;
  const exports = {};
  vm.runInNewContext(compile(capture), {
    exports,
    require(name) {
      if (name === "react") return { useRef: () => ({ current: null }), useCallback: fn => fn };
      if (name === "react/jsx-runtime") return { jsx: (type, props) => ({ type, props }), jsxs: (type, props) => ({ type, props }) };
      if (name.endsWith("submission-capture-guard")) return {
        isFileTransfer: transfer => transfer?.types.includes("Files"),
        useSubmissionCaptureGuard: () => ({ disclose: () => disclosures++ }),
      };
      if (name.endsWith("config/env")) return { publicConfig: { liveAnalysis: false } };
      if (name === "react-dropzone") return { useDropzone: () => assert.fail("Submission mounted react-dropzone") };
      if (name.endsWith("capture-file")) return { validateCaptureFile: () => assert.fail("Submission validated a file") };
      return {};
    },
  });
  const component = exports.CaptureDropzone({ onSelect: () => assert.fail("Retained file") });
  const zone = component.type();
  const input = zone.props.children.find(child => child?.type === "input");
  const nativeInput = { value: "private-path", files: { length: 1 } };
  input.props.onChange({ currentTarget: nativeInput });
  assert.equal(nativeInput.value, "");
  assert.equal(disclosures, 1);
  let prevented = 0;
  zone.props.onDrop({ dataTransfer: { types: ["Files"] }, preventDefault: () => prevented++, currentTarget: {} });
  assert.equal(disclosures, 2);
  assert.equal(prevented, 1);
  zone.props.onDrop({ dataTransfer: { types: ["text/plain"] }, preventDefault: () => assert.fail("Blocked text drag") });
  assert.equal(disclosures, 2);
  input.props.onChange({ currentTarget: { value: "", files: { length: 0 } } });
  assert.equal(disclosures, 2, "Picker cancellation is silent");

  // Execute the exact early script: only file drops are blocked; hydration retires it.
  const earlyScript = layout.match(/strategy="beforeInteractive">\{`([\s\S]*?)`\}/)[1];
  const listeners = new Map();
  vm.runInNewContext(earlyScript, { document: {
    addEventListener: (name, fn) => listeners.set(name, fn),
    removeEventListener: name => listeners.delete(name),
  } });
  listeners.get("drop")({ dataTransfer: { types: ["Files"], items: [] }, preventDefault: () => prevented++ });
  assert.equal(prevented, 2);
  listeners.get("drop")({ dataTransfer: { types: ["text/uri-list"], items: [] }, preventDefault: () => assert.fail("Blocked link drag") });
  listeners.get("submission-guard-ready")();
  assert.ok(!listeners.has("drop") && !listeners.has("dragover"));
  console.log("PASS: V3 static boundaries, nine configuration cases, zero-fetch local refusals, prototype/JSON identity, submission picker/drop handlers, early file-only protection. No browser proof claimed.");
} else {
  const originalResolve = Module._resolveFilename;
  Module._resolveFilename = function(request, ...args) {
    return originalResolve.call(this, request.startsWith("@/") ? path.join(root, request.slice(2)) : request, ...args);
  };
  Module._extensions[".ts"] = (module, file) => module._compile(compile(fs.readFileSync(file, "utf8"), file), file);
  const source = file => load(path.join(root, file));
  const expected = process.argv.at(-1);
  if (expected === "invalid") {
    assert.throws(() => source("lib/config/env.ts"), /NEXT_PUBLIC/);
  } else {
    const { publicConfig } = source("lib/config/env.ts");
    const { getRealAnalysisDataSource, getAnalysisDataSourceForId } = source("lib/api/client.ts");
    const { SubmissionModeDisabledError } = source("lib/api/errors.ts");
    const { ApiAnalysisDataSource } = source("lib/api/api-analysis-data-source.ts");
    const { fetchRealChainDownload, fetchFindingArtifactDownload, createDemoChainDownload } = source("lib/api/export-downloads.ts");
    const { PROTOTYPE_ANALYSIS_ID } = source("mocks/load-prototype-dataset.ts");
    let calls = 0;
    globalThis.fetch = async () => { calls++; throw new Error("Network tripwire"); };
    const demo = await getAnalysisDataSourceForId(PROTOTYPE_ANALYSIS_ID).getResult(PROTOTYPE_ANALYSIS_ID);
    assert.deepEqual(JSON.parse(await createDemoChainDownload(PROTOTYPE_ANALYSIS_ID, demo.chain).blob.text()), demo.chain);
    assert.equal(calls, 0);
    if (expected === "demo") {
      assert.equal(publicConfig.mode, "submission_demo");
      assert.throws(getRealAnalysisDataSource, SubmissionModeDisabledError);
      assert.throws(() => getAnalysisDataSourceForId("ana_ffffffffffffffff"), SubmissionModeDisabledError);
      await assert.rejects(new ApiAnalysisDataSource().getResult("ana_ffffffffffffffff"), SubmissionModeDisabledError);
      await assert.rejects(fetchRealChainDownload("ana_ffffffffffffffff"), SubmissionModeDisabledError);
      await assert.rejects(fetchFindingArtifactDownload(PROTOTYPE_ANALYSIS_ID, demo.chain.findings[0].finding_id, "html"), SubmissionModeDisabledError);
      const { useAnalysisWorkflow } = source("stores/analysis-workflow.ts");
      assert.equal(useAnalysisWorkflow.getState().selectedFile, null);
      useAnalysisWorkflow.getState().selectPrototypeDataset();
      assert.equal(useAnalysisWorkflow.getState().selectedFile, null);
      assert.equal(useAnalysisWorkflow.getState().analysisId, PROTOTYPE_ANALYSIS_ID);
      assert.equal(calls, 0, "Every blocked entry point must fail before fetch");
    } else {
      assert.equal(publicConfig.mode, "backend_connected");
      assert.ok(getRealAnalysisDataSource() instanceof ApiAnalysisDataSource);
      await assert.rejects(getAnalysisDataSourceForId("ana_ffffffffffffffff").getResult("ana_ffffffffffffffff"), /backend is unavailable/);
      assert.equal(calls, 2, "Real failure remains an error with no demo fallback");
    }
  }
}
