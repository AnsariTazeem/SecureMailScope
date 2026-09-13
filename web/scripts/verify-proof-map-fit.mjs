// Lifecycle regression checks with mocked React/React Flow/ResizeObserver.
// These exercise the real hook; browser layout/interaction checks are separate.
import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import vm from "node:vm";

const require = createRequire(import.meta.url);
const ts = require("typescript");
const source = fs.readFileSync(new URL(
  "../src/components/analysis/proof-map/use-initial-proof-map-fit.ts",
  import.meta.url,
), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

function harness() {
  const refs = [];
  let cursor = 0;
  let effect;
  let cleanup;
  const listeners = new Set();
  const observers = new Set();
  const fits = [];
  const container = {
    clientWidth: 0, clientHeight: 0, visible: false,
    checkVisibility() { return this.visible; },
  };
  const state = { width: 0, height: 0, panZoom: null, nodeLookup: new Map() };
  const notify = () => [...listeners].forEach((listener) => listener());
  const store = {
    getState: () => state,
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
  const exports = {};
  vm.runInNewContext(compiled, {
    exports,
    require(name) {
      if (name === "react") return {
        useRef: (initial) => refs[cursor++] ?? (refs[cursor - 1] = { current: initial }),
        useEffect: (callback) => { effect = callback; },
      };
      if (name === "@xyflow/react") return {
        useStoreApi: () => store,
        useReactFlow: () => ({ fitView: (options) => {
          fits.push(options);
          notify(); // fitView's own store update must not recursively refit.
          return Promise.resolve(true);
        } }),
      };
      throw new Error(`Unexpected dependency: ${name}`);
    },
    ResizeObserver: class {
      constructor(callback) { this.callback = callback; }
      observe() { observers.add(this.callback); }
      disconnect() { observers.delete(this.callback); }
    },
  });
  return {
    state, container, fits, notify,
    render(nodes, key = "session-a:all") {
      cleanup?.();
      cursor = 0;
      const ref = exports.useInitialProofMapFit(nodes, key);
      ref.current = container;
      cleanup = effect();
    },
    resize() { [...observers].forEach((callback) => callback()); },
    show() {
      Object.assign(container, { clientWidth: 1000, clientHeight: 704, visible: true });
      Object.assign(state, { width: 1000, height: 704, panZoom: {} });
    },
    measure(nodes) {
      state.nodeLookup = new Map(nodes.map((node) => [node.id, {
        internals: { userNode: node, handleBounds: {} },
        measured: { width: 260, height: 132 },
      }]));
    },
    unmount() {
      cleanup?.();
      assert.equal(listeners.size, 0);
      assert.equal(observers.size, 0);
    },
  };
}

const nodes = [{ id: "capture" }, { id: "session-a" }];
const hidden = harness();
hidden.measure(nodes);
// Stored positive/fallback dimensions must not make a hidden DOM ready.
Object.assign(hidden.state, { width: 500, height: 500, panZoom: {} });
hidden.render(nodes);
hidden.resize();
assert.equal(hidden.fits.length, 0);
hidden.show();
hidden.state.width = 500;
hidden.resize();
assert.equal(hidden.fits.length, 0, "Wait for React Flow's matching viewport size");
hidden.state.width = 1000;
hidden.notify();
assert.equal(hidden.fits.length, 1, "Fit on first visible, measured activation");
assert.equal(hidden.fits[0].duration, 0);
assert.equal(hidden.fits[0].padding, 0.15);
assert.equal(hidden.fits[0].maxZoom, 1);

// Pan/zoom emits store updates; tab hide/show and resize must leave it alone.
hidden.notify();
Object.assign(hidden.container, { clientWidth: 0, clientHeight: 0, visible: false });
hidden.resize();
hidden.show();
hidden.resize();
hidden.notify();
hidden.render(nodes); // Includes effect teardown/replay (Strict Mode).
assert.equal(hidden.fits.length, 1, "Keep the initialized viewport on tab return");

// Investigation and inspection rebuild user node objects but never change layout identity.
for (const action of [
  "start finding investigation",
  "inspect supporting node",
  "inspect supporting edge",
  "close inspector",
  "clear selection",
]) {
  const presented = nodes.map(node => ({ ...node, data: { action } }));
  hidden.render(presented);
  hidden.measure(presented);
  hidden.notify();
  assert.equal(hidden.fits.length, 1, `${action} must preserve the viewport`);
}

const nextNodes = [{ id: "capture" }, { id: "session-b" }];
hidden.render(nextNodes, "session-b:all");
hidden.notify();
assert.equal(hidden.fits.length, 1, "Do not fit the previous session's store nodes");
hidden.measure(nextNodes);
hidden.notify();
assert.equal(hidden.fits.length, 2, "Fit the newly measured session");
hidden.render([nextNodes[1]], "session-b:filtered");
hidden.notify();
assert.equal(hidden.fits.length, 2, "Wait for removed nodes to leave the store");
hidden.measure([nextNodes[1]]);
hidden.notify();
assert.equal(hidden.fits.length, 3, "Preserve fitting after filter changes");
hidden.unmount();

for (const route of ["direct URL", "reload", "standalone"]) {
  const direct = harness();
  direct.show();
  direct.render(nodes);
  direct.resize();
  assert.equal(direct.fits.length, 0, `${route}: wait for nodes`);
  direct.measure(nodes);
  direct.state.nodeLookup.get("capture").measured.width = 0;
  direct.notify();
  assert.equal(direct.fits.length, 0, `${route}: every node must be measured`);
  direct.state.nodeLookup.get("capture").measured.width = 260;
  direct.notify();
  assert.equal(direct.fits.length, 1, `${route}: fit after node measurement`);
  direct.unmount();
}

const empty = harness();
empty.show();
empty.render([]);
empty.notify();
assert.equal(empty.fits.length, 0);
empty.unmount();
console.log("PASS (mocked lifecycle): hidden activation, synchronized viewport/node measurements, one fit per layout, tab return/pan/zoom preservation, effect replay/cleanup, session/filter changes, visible mount/reload/standalone initialization, empty graph.");
