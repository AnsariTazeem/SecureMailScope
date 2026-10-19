/* eslint-disable @typescript-eslint/no-require-imports */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Module = require("node:module");
const { test, after } = require("node:test");
const ts = require("typescript");
const root = path.resolve(__dirname, "..");
const originalResolve = Module._resolveFilename;
const originalTs = Module._extensions[".ts"];
Module._resolveFilename = function (request, parent, ...rest) {
  return originalResolve.call(this, request.startsWith("@/") ? path.join(root, "src", request.slice(2)) : request, parent, ...rest);
};
Module._extensions[".ts"] = (module, filename) => {
  module._compile(ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
  }).outputText, filename);
};
const { ApiAnalysisDataSource } = require("../src/lib/api/api-analysis-data-source.ts");
const capture = () => new File([new Uint8Array([1, 2, 3])], "synthetic.pcapng");
after(() => {
  Module._resolveFilename = originalResolve;
  if (originalTs) Module._extensions[".ts"] = originalTs;
  else delete Module._extensions[".ts"];
});

test("upload retains the real API identity and sends one bounded multipart request", async (t) => {
  let calls = 0;
  t.mock.method(globalThis, "fetch", async (url, init) => {
    calls += 1;
    assert.equal(new URL(url).pathname, "/api/v1/analyses");
    assert.equal(init.method, "POST");
    assert.ok(init.signal instanceof AbortSignal);
    assert.equal(init.body.get("capture").name, "synthetic.pcapng");
    return Response.json({ api_version: "v1", analysis_id: "ana_1234567890abcdef", analysis_status: "complete" }, { status: 201 });
  });
  const result = await new ApiAnalysisDataSource().createAnalysis(capture());
  assert.equal(result.analysis_id, "ana_1234567890abcdef");
  assert.equal(result.data_source, "api");
  assert.equal(calls, 1);
});

test("timed-out upload fails explicitly without a retry or a demo result", async (t) => {
  const controller = new AbortController();
  let calls = 0;
  t.mock.method(AbortSignal, "timeout", (milliseconds) => {
    assert.equal(milliseconds, 120_000);
    return controller.signal;
  });
  t.mock.method(globalThis, "fetch", async (_url, init) => {
    calls += 1;
    assert.equal(init.signal, controller.signal);
    controller.abort(new DOMException("Timed out", "TimeoutError"));
    throw controller.signal.reason;
  });
  await assert.rejects(new ApiAnalysisDataSource().createAnalysis(capture()), (error) => {
    assert.equal(error.code, "backend_timeout");
    assert.match(error.message, /may still be processing/);
    return true;
  });
  assert.equal(calls, 1);
});

test("network and capacity failures never return an analysis identity", async (t) => {
  t.mock.method(globalThis, "fetch", async () => { throw new TypeError("Network error"); });
  await assert.rejects(new ApiAnalysisDataSource().createAnalysis(capture()), { code: "backend_unavailable" });
  t.mock.method(globalThis, "fetch", async () => Response.json({ error: { code: "analysis_capacity", message: "Busy" } }, { status: 503 }));
  await assert.rejects(new ApiAnalysisDataSource().createAnalysis(capture()), { code: "analysis_capacity" });
});

test("duplicate capture remains a rejection, with no automatic second POST", async (t) => {
  let calls = 0;
  t.mock.method(globalThis, "fetch", async () => {
    calls += 1;
    return Response.json({ error: { code: "analysis_conflict", message: "Already held" } }, { status: 409 });
  });
  await assert.rejects(new ApiAnalysisDataSource().createAnalysis(capture()), { code: "analysis_conflict" });
  assert.equal(calls, 1);
});
