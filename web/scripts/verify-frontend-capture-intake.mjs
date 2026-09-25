// Exact-file intake regression; browser interaction remains a separate check.
import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import fs from "node:fs";
import Module, { createRequire } from "node:module";
import { File } from "node:buffer";
import path from "node:path";
import { fileURLToPath } from "node:url";

const load = createRequire(import.meta.url);
const ts = load("typescript");
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(scriptDirectory, "..");
const sourceRoot = path.join(webRoot, "src");
const captureRoot = path.join(webRoot, "public", "captures");
const originalResolve = Module._resolveFilename;

Module._resolveFilename = function (request, ...args) {
  return originalResolve.call(
    this,
    request.startsWith("@/")
      ? path.join(sourceRoot, request.slice(2))
      : request,
    ...args,
  );
};
Module._extensions[".ts"] = (module, filename) =>
  module._compile(
    ts.transpileModule(fs.readFileSync(filename, "utf8"), {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2022,
        esModuleInterop: true,
      },
      fileName: filename,
    }).outputText,
    filename,
  );

globalThis.File = File;
globalThis.crypto ??= webcrypto;

const source = (file) => load(path.join(sourceRoot, file));
const { PREPARED_CAPTURE_BUNDLE, verifyPreparedCaptureBundle } = source(
  "lib/walkthrough/capture-bundle.ts",
);
const manifest = JSON.parse(
  fs.readFileSync(
    path.join(captureRoot, "securemailscope-walkthrough-manifest.json"),
    "utf8",
  ),
);
const dataset = JSON.parse(
  fs.readFileSync(path.join(sourceRoot, "mocks", "prototype-analysis-dataset.json"), "utf8"),
);

const files = PREPARED_CAPTURE_BUNDLE.map((capture, index) => {
  const bytes = fs.readFileSync(path.join(captureRoot, capture.filename));
  const actualHash = createHash("sha256").update(bytes).digest("hex");
  const manifestEntry = manifest.files.find(
    (entry) => entry.filename === capture.filename,
  );
  const datasetEntry = dataset.chain.captures.find(
    (entry) => entry.original_filename_sanitized === capture.filename,
  );
  assert.ok(manifestEntry, `Manifest entry missing for ${capture.filename}`);
  assert.equal(actualHash, capture.sha256);
  assert.ok(datasetEntry, `Dataset entry missing for ${capture.filename}`);
  assert.equal(actualHash, manifestEntry.sha256);
  assert.equal(actualHash, datasetEntry.sha256);
  return new File([bytes], `renamed-${index}.pcapng`, {
    type: "application/octet-stream",
  });
});

const verified = await verifyPreparedCaptureBundle(files);
assert.equal(verified.valid, true, "Exact capture contents must be accepted");
assert.deepEqual(
  verified.canonicalFilenames,
  PREPARED_CAPTURE_BUNDLE.map((capture) => capture.filename),
);

const tamperedBytes = Buffer.from(await files[1].arrayBuffer());
tamperedBytes[0] ^= 0xff;
const tampered = new File([tamperedBytes], "insecure-chain.pcapng", {
  type: "application/octet-stream",
});
assert.equal(
  (await verifyPreparedCaptureBundle([files[0], tampered])).valid,
  false,
  "A one-byte change must be rejected",
);
assert.equal(
  (await verifyPreparedCaptureBundle([files[0], files[0]])).valid,
  false,
  "A duplicate capture must not replace the required pair",
);
assert.equal(
  (await verifyPreparedCaptureBundle([files[0]])).valid,
  false,
  "A partial bundle must be rejected",
);

console.log(
  "PASS: exact capture contents accepted independent of filename; one-byte tamper, duplicate, and partial bundle rejected; source, manifest, and dataset hashes agree.",
);
