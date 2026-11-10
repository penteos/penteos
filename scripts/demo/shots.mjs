#!/usr/bin/env node
/**
 * Screenshots for the website and the README: the real workbench, in English, at 2x, on the demo
 * project from seed.mjs. Throwaway data directory; the tools on PATH are the demo stand-ins.
 *
 *   node scripts/demo/shots.mjs            → PNGs in .demo-shots/
 *   DEMO_STEP=seed node scripts/demo/shots.mjs  → only builds the data and prints what is there
 */
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { conversation, seed } from "./seed.mjs";

const root = resolve(new URL("../..", import.meta.url).pathname);
const out = join(root, ".demo-shots");
mkdirSync(out, { recursive: true });
const dataDir = mkdtempSync(join(tmpdir(), "penteos-demo-"));
// An empty home: the core finds none of this machine's tools (~/go/bin…) or settings.
const home = join(dataDir, "home");
mkdirSync(home, { recursive: true });
// The project's Node (24), called directly so nothing depends on the user's home.
const nodeBin = execFileSync("pnpm", ["exec", "node", "-p", "process.execPath"], { cwd: join(root, "packages", "server"), encoding: "utf8" }).trim();
const PATH = [join(root, "scripts", "demo", "bin"), dirname(nodeBin), "/usr/bin", "/bin"].join(delimiter);
const children = [];
const stop = () => {
  for (const c of children) {
    try {
      process.kill(-c.pid, "SIGTERM");
    } catch {
      /* already gone */
    }
  }
  if (!process.env.DEMO_KEEP) rmSync(dataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
};
process.on("exit", stop);
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => process.exit(1));

/** The core on a free port, with the demo tools first on PATH. */
async function startCore() {
  const core = spawn(nodeBin, ["--conditions=penteos-source", "--import", "tsx", "src/main.ts"], {
    cwd: join(root, "packages", "server"),
    env: { PATH, HOME: home, LANG: "en_US.UTF-8", PENTEOS_DATA_DIR: join(dataDir, "data"), PENTEOS_PORT: "0", PENTEOS_PROXY_PORT: "0", ANTHROPIC_API_KEY: "sk-ant-demo", ANTHROPIC_BASE_URL: "http://127.0.0.1:9" },
    stdio: ["ignore", "pipe", "ignore"],
    detached: true,
  });
  children.push(core);
  const ready = await new Promise((ok, fail) => {
    let buf = "";
    core.stdout.on("data", (d) => {
      buf += String(d);
      const line = buf.split("\n").find((l) => l.startsWith("PENTEOS_READY "));
      if (line) ok(JSON.parse(line.slice("PENTEOS_READY ".length)));
    });
    setTimeout(() => fail(new Error("the core did not start")), 30000);
  });
  const api = async (op, input, token = ready.token) => {
    const r = await fetch(`http://127.0.0.1:${ready.port}/v0/ops/${op}`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(input) });
    const body = await r.json();
    if (!body.ok) throw new Error(`${op}: ${body.error?.message}`);
    // Agents get the text the model reads (JSON, masked); the demo reads it back as data.
    if (body.forModel && typeof body.result === "string") {
      try {
        return JSON.parse(body.result);
      } catch {
        return body.result;
      }
    }
    return body.result;
  };
  return { core, ready, api };
}

const first = await startCore();
const { engagementId } = await seed({ api: first.api, agent: first.ready.agentToken });

if (process.env.DEMO_STEP === "seed") {
  const { api } = first;
  const on = (x = {}) => ({ engagementId, ...x });
  const runs = await api("run.list", on());
  console.log("runs:", (runs.runs ?? runs).map((r) => `${r.status} ${r.command}`).join("\n  "));
  for (const kind of ["host", "service", "domain", "webapp", "endpoint", "technology"]) {
    const items = await api("entity.query", on({ kind }));
    console.log(kind, items.length);
  }
  for (const f of await api("entity.query", on({ kind: "finding" }))) console.log("finding:", f.attributes.severity, f.attributes.status, f.attributes.cvss?.score ?? "-", (f.attributes.evidenceIds ?? []).length, f.attributes.title);
  for (const a of await api("approval.list", on())) console.log("approval:", a.request?.kind ?? a.request?.type, "|", (a.reason ?? "").slice(0, 120), "|", JSON.stringify(a.request).slice(0, 160));
  const plan = await api("plan.get", on());
  console.log("phase:", plan.current);
  console.log("data:", dataDir);
  process.exit(0);
}

// The install proposal the exploitation phase raised on its own is not part of the story.
for (const a of await first.api("approval.list", { engagementId })) {
  if (a.request?.kind === "install_kit") await first.api("approval.reject", { engagementId, approvalId: a.id });
}
const pending = (await first.api("approval.list", { engagementId })).find((a) => a.request?.kind === "exec");

/** The project's folder: the one whose project.json carries its id. */
function projectDir(dir, depth = 0) {
  if (depth > 3 || !existsSync(dir)) return undefined;
  const meta = join(dir, "project.json");
  if (existsSync(meta) && JSON.parse(readFileSync(meta, "utf8")).id === engagementId) return dir;
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (!e.isDirectory()) continue;
    const found = projectDir(join(dir, e.name), depth + 1);
    if (found) return found;
  }
  return undefined;
}
const dir = projectDir(join(dataDir, "data"));
if (!dir) throw new Error("demo project folder not found");

// The Maestro's conversation is read when the core starts: write it, then start the core again.
const closed = (c) => new Promise((r) => (c.exitCode !== null ? r() : c.once("exit", r)));
process.kill(-first.core.pid, "SIGTERM");
await closed(first.core);
mkdirSync(join(dir, "agent"), { recursive: true });
writeFileSync(join(dir, "agent", "conversation.json"), JSON.stringify(conversation({ approvalId: pending?.id })));
const { ready, api } = await startCore();

// Vite, then headless Chrome at 2x (sharp on retina screens and when scaled down).
const require = createRequire(join(root, "packages", "server", "package.json"));
const WebSocket = require("ws");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const vite = spawn("npx", ["vite", "--port", "0", "--strictPort"], { cwd: join(root, "apps", "desktop"), stdio: ["ignore", "pipe", "ignore"], detached: true });
children.push(vite);
const viteUrl = await new Promise((ok, fail) => {
  vite.stdout.on("data", (d) => {
    const m = /Local:\s+(http:\/\/[^\s]+)/.exec(String(d));
    if (m) ok(m[1]);
  });
  setTimeout(() => fail(new Error("vite did not start")), 30000);
});
const [W, H] = (process.env.DEMO_SIZE ?? "1600x1000").split("x").map(Number);
const chrome = spawn(process.env.CHROME ?? "google-chrome", ["--headless=new", "--remote-debugging-port=9335", `--window-size=${W},${H}`, "--no-sandbox", "--disable-gpu", `--user-data-dir=${join(dataDir, "chrome")}`, "about:blank"], { stdio: "ignore", detached: true });
children.push(chrome);
await sleep(1500);
const targets = await (await fetch("http://127.0.0.1:9335/json")).json();
const ws = new WebSocket(targets.find((t) => t.type === "page").webSocketDebuggerUrl);
await new Promise((r) => ws.on("open", r));
let seq = 0;
const waiting = new Map();
const errors = [];
ws.on("message", (m) => {
  const msg = JSON.parse(String(m));
  if (msg.id && waiting.has(msg.id)) waiting.get(msg.id)(msg), waiting.delete(msg.id);
  if (msg.method === "Runtime.exceptionThrown") errors.push(msg.params.exceptionDetails?.exception?.description ?? "exception");
});
const send = (method, params = {}) => new Promise((r) => { const i = ++seq; waiting.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const evaluate = async (expression) => (await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true })).result?.result?.value;
const shot = async (name) => {
  const r = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
  writeFileSync(join(out, `${name}.png`), Buffer.from(r.result.data, "base64"));
  console.log("shot", name);
};
await send("Page.enable");
await send("Runtime.enable");
await send("Emulation.setDeviceMetricsOverride", { width: W, height: H, deviceScaleFactor: 2, mobile: false });
await send("Page.addScriptToEvaluateOnNewDocument", { source: `try { localStorage.setItem("penteos.lang", "en") } catch {}` });
await send("Page.navigate", { url: `${viteUrl}?port=${ready.port}&token=${ready.token}&repo=${root}` });
await sleep(5000);

const open = async (panel, wait = 1200) => {
  await evaluate(`__penteos.workbench.openPanel(${JSON.stringify(panel)})`);
  await sleep(wait);
};
// Close the bottom panel: the screenshots are about the work, not the run log.
await evaluate(`document.querySelector('.bottom .tab-close, .bottom button[aria-label="Close"]')?.click()`);

await open("home");
await shot("01-home");
await open("findings");
await shot("02-findings");
const firstFinding = await api("entity.query", { engagementId, kind: "finding", text: "Jenkins" });
await evaluate(`__penteos.workbench.openFinding(${JSON.stringify(firstFinding[0]?.id)}, ${JSON.stringify(firstFinding[0]?.attributes.title)})`);
await sleep(1500);
await shot("03-finding");
for (const [panel, name] of [["scope", "04-scope"], ["coverage", "05-coverage"], ["hosts", "06-hosts"], ["services", "07-services"], ["board", "08-board"], ["tools", "09-tools"]]) {
  await open(panel);
  await shot(name);
}
await open("report", 1200);
await evaluate(`[...document.querySelectorAll('.report-step')].find((b) => /Generate/.test(b.textContent))?.click()`);
await sleep(800);
await evaluate(`[...document.querySelectorAll('.report-actions button')].find((b) => /Preview/.test(b.textContent))?.click()`);
await sleep(3000);
await shot("10-report");
// The document itself, on its own: the cover and the first finding, as a client reads them.
const html = await evaluate(`document.querySelector('.report-paper')?.srcdoc ?? ""`);
if (html) {
  const frame = (await send("Page.getFrameTree")).result.frameTree.frame.id;
  await send("Page.setDocumentContent", { frameId: frame, html });
  await sleep(1500);
  await shot("11-report-cover");
  const y = await evaluate(`(() => { const h = [...document.querySelectorAll("h2, h3")].find((x) => /Jenkins/.test(x.textContent)); return h ? h.getBoundingClientRect().top + scrollY - 40 : 0; })()`);
  await evaluate(`scrollTo(0, ${Number(y) || 0})`);
  await sleep(500);
  await shot("12-report-finding");
}
if (errors.length) console.log("page errors:", errors.slice(0, 5).join(" | "));
console.log("screenshots in", out);
process.exit(0);
