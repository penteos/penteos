/**
 * What runs first in a code plugin's process, before any of the plugin's
 * code. The process is already started with Node's permission model (it reads only this file and
 * its plugin folder; no writes, child processes, workers or native addons), a memory cap and a
 * clean environment; this file then takes the network away - every module and global that can open
 * a connection or a debugger port - and hands the plugin a small API that only talks to the core.
 * Requests, the graph, storage and secrets all go through the core, under the plugin's permissions:
 * the plugin's code never sees a secret, a socket or a database file.
 *
 * Kept as a string so it ships inside the core bundle; written to the host's folder at start.
 */

export const CODE_RUNNER_VERSION = 1;

export const CODE_RUNNER_SOURCE = String.raw`// Penteos code-plugin runner v${CODE_RUNNER_VERSION} (generated; do not edit)
import * as nodeModule from "node:module";
import { pathToFileURL } from "node:url";

// The channel to the core: one JSON message per line on stdout, marked; the core caps the size of
// each line and how many arrive. Anything the plugin prints itself becomes a log line instead.
const MARK = "\u0001P ";
const rawWrite = process.stdout.write.bind(process.stdout);
const send = (msg) => rawWrite(MARK + JSON.stringify(msg) + "\n");
const asLog = (...parts) => send({ type: "log", text: parts.map((p) => (typeof p === "string" ? p : (() => { try { return JSON.stringify(p); } catch { return String(p); } })())).join(" ").slice(0, 2000) });
for (const k of ["log", "info", "warn", "error", "debug", "trace"]) console[k] = asLog;
process.stdout.write = (chunk) => { asLog(String(chunk)); return true; };

const fail = (message) => {
  try { send({ type: "fatal", error: message }); } catch {}
  setTimeout(() => process.exit(78), 50);
};

// A free plugin (the operator's choice) runs as a normal program: nothing below applies to it.
const FREE = process.env.PENTEOS_PLUGIN_FREE === "1";
if (!FREE) {
  if (typeof nodeModule.registerHooks !== "function" || !process.permission) {
    fail("this runtime cannot isolate code plugins (it needs Node's permission model and module hooks, Node 22.15 or newer)");
  }

  // --- No network, no debugger, no processes: refused however they are reached. ---------------
  const BLOCKED = new Set(["net", "tls", "http", "https", "http2", "dgram", "dns", "dns/promises", "inspector", "inspector/promises", "child_process", "worker_threads", "cluster", "repl", "wasi", "trace_events", "undici", "module"]);
  const bare = (id) => String(id).replace(/^node:/, "");
  const ownModule = nodeModule;
  ownModule.registerHooks({
    resolve(specifier, context, next) {
      if (BLOCKED.has(bare(specifier))) throw new Error("plugins cannot use " + specifier + ": ask the core (penteos.http and the rest)");
      return next(specifier, context);
    },
  });
  const builtin = process.getBuiltinModule?.bind(process);
  Object.defineProperty(process, "getBuiltinModule", {
    value: (id) => {
      if (BLOCKED.has(bare(id))) throw new Error("plugins cannot use " + id);
      return builtin(id);
    },
    writable: false,
    configurable: false,
  });
  for (const name of ["fetch", "WebSocket", "EventSource", "XMLHttpRequest", "Request", "Response", "Headers", "FormData"]) {
    try { Object.defineProperty(globalThis, name, { value: undefined, writable: false, configurable: false }); } catch {}
  }
  for (const name of ["binding", "_linkedBinding", "dlopen"]) {
    try { Object.defineProperty(process, name, { value: () => { throw new Error("not available to plugins"); }, writable: false, configurable: false }); } catch {}
  }
}

// --- The bridge to the core. ------------------------------------------------------------------
let seq = 0;
const waiting = new Map();
const handlers = new Map();

function ask(callId, step) {
  return new Promise((resolve, reject) => {
    const id = ++seq;
    waiting.set(id, { resolve, reject });
    send({ type: "rpc", id, callId, step });
  });
}

function toBase64(data) {
  if (typeof data === "string") return Buffer.from(data, "utf8").toString("base64");
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString("base64");
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("base64");
  return Buffer.from(JSON.stringify(data, null, 2), "utf8").toString("base64");
}

function api(callId, input, engagement, output) {
  const step = (s) => ask(callId, s);
  return Object.freeze({
    input,
    engagement,
    /**
     * Files for the operator, in the project's folder (they show up to download or open, and travel
     * with the project). write(name, data): data is a string, bytes or any JSON value. A free plugin
     * also gets dir, that folder, to write there itself with any library.
     */
    files: Object.freeze({
      write: (name, data) => step({ do: "file", name, content: toBase64(data), encoding: "base64" }),
      dir: output,
    }),
    /** One HTTPS request, made by the core to a host of the plugin's net: permissions. Secrets go as "{{settings.x}}" or "{{secret:x}}" and are filled in by the core. */
    http: (req) => step({ do: "http", ...req }),
    graph: Object.freeze({
      query: (kind, opts = {}) => step({ do: "graph_query", kind, ...opts }),
      get: (entity) => step({ do: "graph_get", entity }),
      put: (type, attributes, opts = {}) => step({ do: "put", type, attributes, ...opts }),
      annotate: (entity, data) => step({ do: "annotate", entity, data }),
      relate: (from, to) => step({ do: "relate", from, to }),
    }),
    store: Object.freeze({
      insert: (table, row, opts = {}) => step({ do: "store_insert", table, row, ...opts }),
      insertMany: (table, rows, opts = {}) => step({ do: "store_insert", table, rows, ...opts }),
      query: (table, opts = {}) => step({ do: "store_query", table, ...opts }),
      update: (table, where, set, opts = {}) => step({ do: "store_update", table, where, set, ...opts }),
      delete: (table, where, opts = {}) => step({ do: "store_delete", table, where, ...opts }),
    }),
    findingDraft: (finding) => step({ do: "finding_draft", ...finding }),
    notify: (title, body, level = "info") => step({ do: "notify", title, ...(body ? { body } : {}), level }),
    /**
     * The official deliverable with this plugin's choices (needs graph:read and files:write): a Word
     * document by default, saved among its files. report({ title, author, company, color, logo,
     * sections, skip, minSeverity, includeDrafts, extra: [{ title, markdown, after }], name, format }).
     */
    report: (options = {}) => step({ do: "report", ...options }),
    /** The plugin's settings, without the secret ones (those never reach the plugin). */
    settings: () => step({ do: "settings" }),
    log: asLog,
  });
}

const onMessage = async (m) => {
  if (!m || typeof m !== "object") return;
  if (m.type === "rpc_result") {
    const w = waiting.get(m.id);
    if (!w) return;
    waiting.delete(m.id);
    if (m.ok) w.resolve(m.value);
    else w.reject(new Error(m.error));
    return;
  }
  if (m.type === "call") {
    const handler = handlers.get(m.handler);
    try {
      if (!handler) throw new Error("no handler " + m.handler);
      const value = await handler(m.input, api(m.id, m.input, m.engagement, m.output));
      send({ type: "return", id: m.id, ok: true, value: value === undefined ? null : JSON.parse(JSON.stringify(value)) });
    } catch (e) {
      send({ type: "return", id: m.id, ok: false, error: String(e && e.message ? e.message : e).slice(0, 2000) });
    }
  }
};
// Messages from the core: one JSON per line on stdin.
let inbox = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  inbox += chunk;
  let nl;
  while ((nl = inbox.indexOf("\n")) >= 0) {
    const line = inbox.slice(0, nl);
    inbox = inbox.slice(nl + 1);
    try { void onMessage(JSON.parse(line)); } catch {}
  }
});
process.stdin.on("end", () => process.exit(0));

// --- The plugin. ------------------------------------------------------------------------------
const main = process.argv[2];
try {
  const mod = await import(pathToFileURL(main).href);
  const activate = mod.activate ?? mod.default?.activate;
  if (typeof activate !== "function") throw new Error("the plugin's main module exports no activate(penteos)");
  await activate(Object.freeze({
    /** Registers an operation's code: the manifest says its name, input, title and who may call it. */
    operation: (name, fn) => {
      if (typeof fn !== "function") throw new Error("operation " + name + " needs a function");
      handlers.set(String(name), fn);
    },
  }));
  send({ type: "ready", handlers: [...handlers.keys()] });
} catch (e) {
  fail("activation failed: " + String(e && e.message ? e.message : e).slice(0, 1000));
}
`;
