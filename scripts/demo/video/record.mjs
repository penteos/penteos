#!/usr/bin/env node
/**
 * The launch video: a real Penteos run against OWASP Juice Shop, filmed in headless Chrome and
 * encoded with ffmpeg. Nothing is staged in the data: the Maestro runs on a real model (DeepSeek)
 * against a real lab, the scope gate answers for real, the report is the one Penteos writes. The
 * edit only cuts waits and speeds the Maestro's work up (shown on screen as a time-lapse, with the
 * real minutes it took).
 *
 *   DEEPSEEK_API_KEY=… node scripts/demo/video/record.mjs
 *     DEMO_TARGET_HOST   the lab's name, resolving to it (default juice-shop.test, see /etc/hosts)
 *     DEMO_MINUTES       the most the Maestro may work (default 28)
 *     DEMO_DRY=1         no Maestro: films the other scenes only (to check the stage)
 *     DEMO_OUT           output folder (default .demo-video/)
 *
 * Output: penteos-demo.mp4 (1920x1080), run.json (what happened), and the frames.
 */
import { execFileSync, spawn } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(new URL("../../..", import.meta.url).pathname);
const OUT = resolve(process.env.DEMO_OUT ?? join(root, ".demo-video"));
const FRAMES = join(OUT, "frames");
rmSync(FRAMES, { recursive: true, force: true });
mkdirSync(FRAMES, { recursive: true });
const HOST = process.env.DEMO_TARGET_HOST ?? "juice-shop.test";
const TARGET = `http://${HOST}`;
const MINUTES = Number(process.env.DEMO_MINUTES ?? 28);
const DRY = process.env.DEMO_DRY === "1";
const LAPSE_SECONDS = 24; // the Maestro's work, however long, plays in this many seconds

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
const dataDir = mkdtempSync(join(tmpdir(), "penteos-video-"));
const home = join(dataDir, "home");
mkdirSync(home, { recursive: true });
const children = [];
const stop = () => {
  for (const c of children) {
    try {
      process.kill(-c.pid, "SIGTERM");
    } catch {
      /* already gone */
    }
  }
  rmSync(join(root, "apps", "desktop", "stage.html"), { force: true });
  rmSync(dataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
};
process.on("exit", stop);
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => process.exit(1));

// ---------------------------------------------------------------------------------------------
// 1. The core, with the model's key and an empty home.

const nodeBin = execFileSync("pnpm", ["exec", "node", "-p", "process.execPath"], { cwd: join(root, "packages", "server"), encoding: "utf8" }).trim();
const core = spawn(nodeBin, ["--conditions=penteos-source", "--import", "tsx", "src/main.ts"], {
  cwd: join(root, "packages", "server"),
  env: {
    PATH: process.env.PATH,
    HOME: home,
    LANG: "en_US.UTF-8",
    PENTEOS_DATA_DIR: join(dataDir, "data"),
    PENTEOS_PORT: "0",
    PENTEOS_PROXY_PORT: "0",
    ...(process.env.DEEPSEEK_API_KEY ? { DEEPSEEK_API_KEY: process.env.DEEPSEEK_API_KEY } : {}),
  },
  stdio: ["ignore", "pipe", "inherit"],
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
  setTimeout(() => fail(new Error("the core did not start")), 60000);
});
const api = async (op, input = {}, token = ready.token) => {
  const r = await fetch(`http://127.0.0.1:${ready.port}/v0/ops/${op}`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(input) });
  const body = await r.json();
  if (!body.ok) throw new Error(`${op}: ${body.error?.message}`);
  return body.result;
};

// The project, as an operator sets it up before a round: the scope itself is added on camera.
await api("workspace.set_prefs", { onboarded: true, workStyle: "solo" });
const eng = await api("engagement.create", { clientName: "OWASP Juice Shop", name: "Web assessment", mode: "web", language: "en" });
const engagementId = eng.id;
const on = (x = {}) => ({ engagementId, ...x });
await api("engagement.update", on({ maxRisk: "exploitation", autonomy: "maestro_auto" }));
await api("tool.set_auto_install", on({ enabled: true, maxMB: 3000 }));
// The workbench opens the operator's active project: make it this one (the core started on the
// lab project it creates on a first run).
{
  const WS = createRequire(join(root, "packages", "server", "package.json"))("ws");
  const sock = new WS(`ws://127.0.0.1:${ready.port}/v0/ws?token=${ready.token}`);
  await new Promise((ok, fail) => (sock.on("open", ok), sock.on("error", fail)));
  sock.send(JSON.stringify({ t: "activate", engagementId }));
  await sleep(800);
  sock.close();
}
// The usual web kit, installed before filming (verified downloads; nothing to watch).
for (const tool of DRY ? [] : ["httpx", "katana", "nuclei", "ffuf"]) {
  try {
    await api("tool.install", on({ tool }));
    log("installed", tool);
  } catch (e) {
    log("install", tool, "failed:", e.message);
  }
}

// ---------------------------------------------------------------------------------------------
// 2. Vite serves the app and the stage (same origin), Chrome films the stage.

copyFileSync(join(root, "scripts", "demo", "video", "stage.html"), join(root, "apps", "desktop", "stage.html"));
const vite = spawn("npx", ["vite", "--port", "0", "--strictPort"], { cwd: join(root, "apps", "desktop"), stdio: ["ignore", "pipe", "ignore"], detached: true });
children.push(vite);
const viteUrl = await new Promise((ok, fail) => {
  vite.stdout.on("data", (d) => {
    const m = /Local:\s+(http:\/\/[^\s]+)/.exec(String(d).replace(/\x1b\[[0-9;]*m/g, ""));
    if (m) ok(m[1].replace(/\/$/, ""));
  });
  setTimeout(() => fail(new Error("vite did not start")), 60000);
});
const require = createRequire(join(root, "packages", "server", "package.json"));
const WebSocket = require("ws");
const chrome = spawn(process.env.CHROME ?? "google-chrome", ["--headless=new", "--remote-debugging-port=9337", "--window-size=1920,1080", "--no-sandbox", "--autoplay-policy=no-user-gesture-required", "--hide-scrollbars", "--font-render-hinting=none", `--user-data-dir=${join(dataDir, "chrome")}`, "about:blank"], { stdio: "ignore", detached: true });
children.push(chrome);
// Chrome takes its time on a cold machine: wait for its DevTools endpoint.
let page;
for (let i = 0; i < 60 && !page; i++) {
  await sleep(500);
  page = await fetch("http://127.0.0.1:9337/json")
    .then((r) => r.json())
    .then((list) => list.find((t) => t.type === "page"))
    .catch(() => undefined);
}
if (!page) throw new Error("Chrome did not start");
const ws = new WebSocket(page.webSocketDebuggerUrl, { maxPayload: 256 * 1024 * 1024 });
await new Promise((r) => ws.on("open", r));
let seq = 0;
const waiting = new Map();
const pageErrors = [];

// The film: every frame Chrome paints, with its time and the speed it plays at.
const frames = [];
let speed = 1; // 1 = real time; >1 = time-lapse; Infinity = cut
ws.on("message", (m) => {
  const msg = JSON.parse(String(m));
  if (msg.id && waiting.has(msg.id)) waiting.get(msg.id)(msg), waiting.delete(msg.id);
  if (msg.method === "Runtime.exceptionThrown") pageErrors.push(msg.params.exceptionDetails?.exception?.description ?? "exception");
  if (msg.method === "Page.screencastFrame") {
    const { data, metadata, sessionId } = msg.params;
    ws.send(JSON.stringify({ id: ++seq, method: "Page.screencastFrameAck", params: { sessionId } }));
    const file = `f${String(frames.length).padStart(6, "0")}.jpg`;
    writeFileSync(join(FRAMES, file), Buffer.from(data, "base64"));
    frames.push({ file, t: metadata.timestamp, speed });
  }
});
const send = (method, params = {}) =>
  new Promise((r) => {
    const i = ++seq;
    waiting.set(i, r);
    ws.send(JSON.stringify({ id: i, method, params }));
  });
const js = async (expression) => {
  const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (r.result?.exceptionDetails) throw new Error(`${expression.slice(0, 80)}: ${r.result.exceptionDetails.exception?.description ?? r.result.exceptionDetails.text}`);
  return r.result?.result?.value;
};
const stage = (call) => js(`stage.${call}`);
const S = (v) => JSON.stringify(v);

await send("Page.enable");
await send("Runtime.enable");
await send("Emulation.setDeviceMetricsOverride", { width: 1920, height: 1080, deviceScaleFactor: 1, mobile: false });
await send("Page.addScriptToEvaluateOnNewDocument", { source: `try { localStorage.setItem("penteos.lang", "en") } catch {}` });
await send("Page.navigate", { url: `${viteUrl}/stage.html` });
await sleep(1500);
await stage(`card("intro", true)`);
await stage(`load(${S(`${viteUrl}/?port=${ready.port}&token=${ready.token}`)}, "Penteos · OWASP Juice Shop · Web assessment")`);
for (let i = 0; i < 60 && !(await stage("ready()")); i++) await sleep(500);
await sleep(4000); // fonts, the hero video, the app's first paint

/** Waits until the app shows something (selector or {text}). */
const until = async (q, ms = 15000) => {
  for (let t = 0; t < ms; t += 300) {
    if (await stage(`exists(${S(q)})`)) return true;
    await sleep(300);
  }
  log("not found:", JSON.stringify(q));
  return false;
};
const openPanel = (id) => stage(`inApp(${S("(w, id) => w.__penteos.workbench.openPanel(id)")}, ${S(id)})`);
const caption = (k, html) => stage(`caption(${S(k)}, ${S(html)})`);
/** Runs fn without filming it (setup between scenes). */
const cut = async (fn) => {
  speed = Infinity;
  try {
    return await fn();
  } finally {
    speed = 1;
  }
};

await send("Page.startScreencast", { format: "jpeg", quality: 90, maxWidth: 1920, maxHeight: 1080, everyNthFrame: 1 });
const run = { started: new Date().toISOString(), target: TARGET, scenes: [] };
const scene = (name) => {
  run.scenes.push({ name, at: frames.length });
  log("scene", name);
};

// ---------------------------------------------------------------------------------------------
// Intro.
scene("intro");
await sleep(5200);
await cut(async () => {
  // No AI on this machine (a dry run): the window that offers one is not part of the film.
  if (await stage(`exists(${S({ text: "Later", sel: "button" })})`)) await stage(`click(${S({ text: "Later", sel: "button" })})`);
  await openPanel("scope");
  await stage(`cursor(true)`);
  await sleep(800);
});
await stage(`card("intro", false)`);
await sleep(900);

// ---------------------------------------------------------------------------------------------
// Scope, on camera: the lab in, a payment host out, then the gate asked about it.
scene("scope");
await caption("Scope", "You set the scope. <em>The core enforces it.</em>");
await until(".scope-form input.mono");
await stage(`click(".scope-form input.mono")`);
await stage(`type(".scope-form input.mono", ${S(HOST)})`);
await stage(`click(".scope-form input.input:not(.mono)")`);
await stage(`type(".scope-form input.input:not(.mono)", "Lab target: OWASP Juice Shop")`);
await stage(`click({ text: "Add rule", sel: ".scope-form button" })`);
await sleep(900);
await stage(`click({ text: "Exclude", sel: ".scope-form .seg button" })`);
await stage(`click(".scope-form input.mono")`);
await stage(`type(".scope-form input.mono", ${S(`pay.${HOST}`)})`);
await stage(`click(".scope-form input.input:not(.mono)")`);
await stage(`type(".scope-form input.input:not(.mono)", "Payment provider: not authorized")`);
await stage(`click({ text: "Add rule", sel: ".scope-form button" })`);
await sleep(1200);
await caption("Scope gate", "Out of scope is blocked by the core. <em>Not by a prompt.</em>");
await stage(`click("input[placeholder^='Target to check']")`);
await stage(`type("input[placeholder^='Target to check']", ${S(`https://pay.${HOST}/checkout`)})`);
await stage(`click({ text: "Check", sel: "button" })`);
await until(".verdict");
await stage(`highlight(".verdict", "Denied before anything is sent", true)`);
await sleep(3800);
await stage(`highlight(null)`);

// ---------------------------------------------------------------------------------------------
// The Maestro: one instruction, then the work, sped up.
scene("maestro");
await caption("The Maestro", "One instruction. <em>Any model:</em> ChatGPT, DeepSeek, local.");
await cut(() => openPanel("coverage"));
const composer = ".composer textarea";
await until(composer);
const ask = `Assess the web app at ${TARGET}: map it, then test authentication, access control and injection. Prove every finding with evidence.`;
await stage(`click(${S(composer)})`);
await stage(`type(${S(composer)}, ${S(ask)}, 40)`);
await sleep(500);
const maestroStart = Date.now();
if (!DRY) await stage(`enter(${S(composer)})`);
await sleep(4000);

scene("lapse");
await caption("Autopilot", "It maps, tests and proves. <em>Every step inside the scope.</em>");
await stage(`cursor(false)`);
const running = () => stage(`exists({ text: "Stop", sel: ".composer button" })`);
if (!DRY) {
  const panels = ["coverage", "findings", "board", "hosts", "findings"];
  let shown = -1;
  const limit = MINUTES * 60_000;
  await sleep(10_000);
  speed = 40; // provisional; the encoder applies the real factor
  const lapseFrom = frames.length;
  while (Date.now() - maestroStart < limit) {
    const elapsed = Date.now() - maestroStart;
    const minutes = Math.floor(elapsed / 60_000);
    await stage(`lapse(true, ${S(`${minutes} min of real work`)})`);
    const want = Math.min(panels.length - 1, Math.floor((elapsed / limit) * panels.length));
    if (want !== shown) {
      shown = want;
      await openPanel(panels[want]);
    }
    if (!(await running())) {
      // Finished, or waiting on the operator: give it a moment to start again before calling it done.
      await sleep(20_000);
      if (!(await running())) break;
    }
    await sleep(10_000);
  }
  if (await running()) await stage(`click({ text: "Stop", sel: ".composer button" })`);
  run.maestroMinutes = Math.round((Date.now() - maestroStart) / 6000) / 10;
  run.lapse = { from: lapseFrom, to: frames.length };
  await stage(`lapse(false)`);
  speed = 1;
}
await sleep(1500);

// ---------------------------------------------------------------------------------------------
// What the model saw: markers in the Maestro's own words, the real values only here.
scene("privacy");
// A marker as the vault writes it: «email:3», «card:1 …».
const markerQ = { re: "«[a-z_]+:\\d+", sel: "p, li, code, span, td" };
await caption("Privacy", "The model reads <em>«email:3»</em>. The real address never leaves your machine.");
if (await stage(`exists(${S(markerQ)})`)) {
  await stage(`zoom(${S(markerQ)}, 1.7)`);
  await sleep(1500);
  await stage(`highlight(${S(markerQ)}, "What the AI sees")`);
  await sleep(4200);
  await stage(`highlight(null)`);
  await stage(`zoom(null)`);
  await sleep(1400);
  run.markerShown = true;
}
await cut(() => openPanel("metrics"));
const statQ = { text: "Privacy towards the model", sel: "section" };
await until(statQ, 6000);
if (await stage(`exists(${S(statQ)})`)) {
  await stage(`highlight(${S(statQ)}, "Masked before the model read it")`);
  await sleep(3800);
  await stage(`highlight(null)`);
}

// ---------------------------------------------------------------------------------------------
// Findings: each one with its proof; the operator approves.
scene("findings");
const findings = await api("entity.query", on({ kind: "finding", limit: 50 })).catch(() => []);
run.findings = findings.map((f) => ({ title: f.attributes.title, severity: f.attributes.severity, status: f.attributes.status, evidence: (f.attributes.evidenceIds ?? []).length }));
await caption("Findings", "No proof, <em>no finding.</em>");
await cut(() => openPanel("findings"));
await sleep(1600);
const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const best = [...findings].filter((f) => (f.attributes.evidenceIds ?? []).length).sort((a, b) => (rank[a.attributes.severity] ?? 9) - (rank[b.attributes.severity] ?? 9))[0] ?? findings[0];
if (best) {
  await stage(`cursor(true)`);
  const title = best.attributes.title;
  if (await stage(`point(${S({ text: title.slice(0, 40) })})`)) await sleep(600);
  await stage(`inApp(${S("(w, id, t) => w.__penteos.workbench.openFinding(id, t)")}, ${S(best.id)}, ${S(title)})`);
  await sleep(2200);
  const evQ = { text: "Evidence", sel: "h2, h3, h4, .section-title, b, strong" };
  if (await stage(`exists(${S(evQ)})`)) {
    await stage(`point(${S(evQ)})`);
    await stage(`zoom(${S(evQ)}, 1.35)`);
    await sleep(3600);
    await stage(`zoom(null)`);
    await sleep(1200);
  } else await sleep(3000);
  await caption("You decide", "Nothing reaches the report <em>without you.</em>");
  const approveQ = { text: "Approve", sel: "button" };
  if (await stage(`exists(${S(approveQ)})`)) {
    await stage(`click(${S(approveQ)})`);
    run.approvedOnCamera = true;
  }
  await sleep(2600);
}

// ---------------------------------------------------------------------------------------------
// The report.
scene("report");
await caption("Report", "The report writes itself. <em>DOCX, PDF, HTML, Markdown.</em>");
await cut(() => openPanel("report"));
await sleep(1200);
const genQ = { text: "Generate", sel: ".report-step, button" };
if (await stage(`exists(${S(genQ)})`)) await stage(`click(${S(genQ)})`);
await sleep(1200);
const prevQ = { text: "Preview", sel: ".report-actions button, button" };
if (await stage(`exists(${S(prevQ)})`)) await stage(`click(${S(prevQ)})`);
await until(".report-paper", 20000);
await sleep(2500);
await stage(`cursor(false)`);
// The report is a sandboxed frame: it scrolls with the wheel, as a person would scroll it.
const paper = await stage(`center(".report-paper")`);
if (paper) {
  await sleep(1500);
  for (let i = 0; i < 40; i++) {
    await send("Input.dispatchMouseEvent", { type: "mouseWheel", x: paper.x, y: paper.y, deltaX: 0, deltaY: 45 });
    await sleep(45);
  }
  await sleep(2500);
  for (let i = 0; i < 40; i++) {
    await send("Input.dispatchMouseEvent", { type: "mouseWheel", x: paper.x, y: paper.y, deltaX: 0, deltaY: 45 });
    await sleep(45);
  }
  await sleep(2500);
}
await stage(`zoom(null)`);
await caption("", "");
await sleep(1200);

// ---------------------------------------------------------------------------------------------
// End card.
scene("outro");
await stage(`card("outro", true)`);
await sleep(6500);
await send("Page.stopScreencast");
await sleep(500);

// ---------------------------------------------------------------------------------------------
// 3. The cut: each frame lasts until the next one, divided by its speed; the time-lapse is
// fitted to LAPSE_SECONDS whatever the Maestro took.
if (run.lapse) {
  const a = frames[run.lapse.from];
  const b = frames[run.lapse.to - 1];
  const real = a && b ? b.t - a.t : 0;
  const factor = real > LAPSE_SECONDS ? real / LAPSE_SECONDS : 1;
  for (let i = run.lapse.from; i < run.lapse.to; i++) frames[i].speed = factor;
  run.lapse.factor = Math.round(factor);
}
const lines = [];
for (let i = 0; i < frames.length; i++) {
  const f = frames[i];
  if (f.speed === Infinity) continue;
  const next = frames[i + 1];
  const d = next ? (next.t - f.t) / f.speed : 2;
  if (d <= 0) continue;
  lines.push(`file '${join(FRAMES, f.file)}'`, `duration ${d.toFixed(4)}`);
}
lines.push(`file '${join(FRAMES, frames[frames.length - 1].file)}'`);
writeFileSync(join(OUT, "frames.txt"), lines.join("\n") + "\n");
const mp4 = join(OUT, "penteos-demo.mp4");
execFileSync("ffmpeg", ["-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", join(OUT, "frames.txt"), "-vf", "fps=30,format=yuv420p", "-c:v", "libx264", "-preset", DRY ? "veryfast" : "slow", "-crf", "18", "-movflags", "+faststart", mp4], { stdio: "inherit" });
run.frames = frames.length;
run.masked = await api("privacy.report", on()).then((p) => p.masked).catch(() => ({}));
run.pageErrors = pageErrors.slice(0, 10);
writeFileSync(join(OUT, "run.json"), JSON.stringify(run, null, 2));
log("video:", mp4);
log(JSON.stringify({ findings: run.findings?.length, masked: run.masked, minutes: run.maestroMinutes, lapse: run.lapse }));
process.exit(0);
