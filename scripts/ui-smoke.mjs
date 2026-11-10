#!/usr/bin/env node
/**
 * Visual smoke test: starts a core with a throwaway data directory and the Vite dev server,
 * drives the renderer in headless Chrome over the DevTools protocol, opens every section and
 * saves a screenshot of each. Fails on console errors or on a section that does not render.
 *
 *   pnpm ui:smoke            → screenshots in .smoke/es/ (ignored by git)
 *   SMOKE_SIZE=1440x900 pnpm ui:smoke  → at a laptop's size
 *   SMOKE_LANG=en pnpm ui:smoke  → the same in English, in .smoke/en/; missing catalog keys fail the run
 *   CHROME=/path/to/chrome   → another Chromium build
 */
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createRequire } from "node:module";

const root = resolve(new URL("..", import.meta.url).pathname);
const require = createRequire(join(root, "packages", "server", "package.json"));
const WebSocket = require("ws");
const LANG = process.env.SMOKE_LANG === "en" ? "en" : "es";
// SMOKE_SIZE=1440x900 to check a laptop screen (default 1600x1000).
const [W, H] = (process.env.SMOKE_SIZE ?? "1600x1000").split("x").map(Number);
const out = join(root, ".smoke", LANG);
/** Sample data in the run's language, so an English run shows no Spanish that is not a bug. */
const L = (es, en) => (LANG === "en" ? en : es);
mkdirSync(out, { recursive: true });
const dataDir = mkdtempSync(join(tmpdir(), "penteos-smoke-"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const children = [];
// Children run in their own process group: pnpm and npx start the real servers as grandchildren,
// and killing only the wrapper would leave them running.
const stop = () => {
  for (const c of children) {
    try {
      process.kill(-c.pid, "SIGTERM");
    } catch {
      /* already gone */
    }
  }
  rmSync(dataDir, { recursive: true, force: true });
};
process.on("exit", stop);
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => process.exit(1));

// 0. A plugin that took the previous start down while activating: an
// approved plugin and the crash marker left on disk. This start must blame it, disable it and tell
// the operator - the notice is checked and captured below.
{
  const pluginDir = join(dataDir, "plugins", "lab-shodan");
  mkdirSync(pluginDir, { recursive: true });
  writeFileSync(join(pluginDir, "plugin.json"), JSON.stringify({ id: "lab.shodan", name: "Shodan (lab)", version: "1.0.0", apiVersion: 1, level: "declarative", author: { type: "human" }, permissions: ["net:api.shodan.io"] }));
  mkdirSync(join(dataDir, "plugin-host"), { recursive: true });
  writeFileSync(join(dataDir, "plugin-host", "state.json"), JSON.stringify({ version: 1, failedBoots: 0, notices: [], plugins: { "lab.shodan": { enabled: true, hash: "smoke", name: "Shodan (lab)", errors: [], timeouts: [], crashes: [] } } }));
  writeFileSync(join(dataDir, "plugin-host", "activating.json"), JSON.stringify({ id: "lab.shodan", name: "Shodan (lab)", at: new Date().toISOString() }));
}

// 0b. A working declarative plugin: found waiting for approval, approved
// and enabled in the project below, then used from its generated forms and its menus.
const NOTES_PLUGIN = {
  id: "lab.notes",
  name: "Notas de campo (lab)",
  version: "1.0.0",
  apiVersion: 1,
  level: "declarative",
  author: { type: "human", name: "Lab" },
  description: "Anota hosts y guarda notas de campo en el proyecto.",
  permissions: ["graph:read", "graph:write", "ui:menu"],
  contributes: {
    annotations: [{ on: ["host"], fields: [{ name: "note", type: "string" }] }],
    storage: { project: [{ version: 1, steps: [{ op: "create_table", table: "notes", columns: [{ name: "host", type: "text", required: true }, { name: "text", type: "text", required: true }] }] }] },
    operations: [
      {
        name: "annotate_host",
        title: { es: "Anotar host", en: "Annotate host" },
        description: { es: "Deja una nota sobre un host y la guarda en el registro de campo.", en: "Leaves a note on a host and keeps it in the field log." },
        input: [
          { name: "ip", type: "host", required: true, label: "IP" },
          { name: "note", type: "string", required: true, label: { es: "Nota", en: "Note" }, placeholder: { es: "Qué vio", en: "What you saw" } },
        ],
        steps: [
          { do: "graph_query", id: "h", kind: "host", text: "{{input.ip}}" },
          { do: "fail", if: "{{steps.h | empty}}", message: "No host {{input.ip}} in the project" },
          { do: "annotate", entity: "{{steps.h[0].id}}", data: { note: "{{input.note}}" } },
          { do: "store_insert", table: "notes", row: { host: "{{input.ip}}", text: "{{input.note}}" } },
        ],
        result: { ip: "{{input.ip}}", note: "{{input.note}}" },
        view: { type: "message", text: "{{result.ip}}: {{result.note}}" },
      },
      {
        name: "list_notes",
        title: { es: "Ver notas de campo", en: "Field notes" },
        description: { es: "Las notas de campo de este proyecto.", en: "This project's field notes." },
        steps: [{ do: "store_query", table: "notes", orderBy: { column: "id", dir: "desc" } }],
        view: { type: "table", columns: [{ field: "host", label: "Host" }, { field: "text", label: { es: "Nota", en: "Note" } }, { field: "created_at", label: { es: "Fecha", en: "Date" } }] },
      },
    ],
    menus: [
      { id: "annotate", title: { es: "Anotar", en: "Annotate" }, operation: "annotate_host", where: "entity", kinds: ["host"], prefill: { ip: "{{entity.attributes.ip}}" } },
      { id: "notes", title: { es: "Notas de campo", en: "Field notes" }, operation: "list_notes", where: "plugins", direct: true },
    ],
  },
};
{
  const dir = join(dataDir, "plugins", "lab-notes");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "plugin.json"), JSON.stringify(NOTES_PLUGIN));
}

// 0c. A code plugin with panels: its code runs isolated; its panel tries the network (the
// policy must block it) and then calls its own operation through the bridge.
{
  const dir = join(dataDir, "plugins", "lab-panel");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "plugin.json"), JSON.stringify({
    id: "lab.panel", name: "Panel (lab)", version: "1.0.0", apiVersion: 1, level: "code", main: "main.mjs",
    author: { type: "human", name: "Lab" },
    description: { es: "Plugin de código de laboratorio con paneles.", en: "Lab code plugin with panels." },
    permissions: ["graph:read", "graph:write", "ui:panel"],
    contributes: {
      entityTypes: [{ name: "mark", label: "Mark", fields: [{ name: "note", type: "string", required: true }, { name: "fetchBlocked", type: "boolean" }], key: ["note"] }],
      operations: [{ name: "mark", title: "Mark", description: "Leaves a mark.", handler: "mark", actors: ["human"], input: [{ name: "note", type: "string", required: true }, { name: "fetchBlocked", type: "boolean" }] }],
      panels: [
        { id: "main", title: { es: "Panel de prueba", en: "Test panel" }, file: "panel.html" },
        { id: "host", title: "Host", file: "panel.html", where: "entity", kinds: ["host"], height: 140 },
      ],
    },
  }));
  writeFileSync(join(dir, "main.mjs"), "export async function activate(p) { p.operation('mark', async (input, penteos) => (await penteos.graph.put('mark', { note: input.note, fetchBlocked: input.fetchBlocked })).id); }\n");
  writeFileSync(join(dir, "panel.html"), `<!doctype html><html><head><style>body{font:13px sans-serif;color:#ddd;background:#16131c;margin:12px}</style></head><body><div id="x">…</div><script>
(async () => {
  let blocked = false;
  try { await fetch(new URL("/v0/health", location.href)); } catch { blocked = true; }
  const where = penteos.context.entityId ? "entity" : "tab";
  const id = await penteos.call("mark", { note: "from-panel-" + where, fetchBlocked: blocked });
  document.getElementById("x").textContent = "Panel " + where + " · network " + (blocked ? "blocked" : "OPEN") + " · mark " + id;
})();
</script></body></html>`);
}

// 1. The core, on a free port, with a placeholder API key so the team level is selectable. The
// provider points at a closed local port: nothing the core tries (the verifier…) leaves this machine.
const core = spawn("pnpm", ["--silent", "dev"], {
  cwd: join(root, "packages", "server"),
  env: { ...process.env, PENTEOS_DATA_DIR: dataDir, PENTEOS_PORT: "0", PENTEOS_PROXY_PORT: "0", ANTHROPIC_API_KEY: "sk-ant-smoke", ANTHROPIC_BASE_URL: "http://127.0.0.1:9" },
  stdio: ["ignore", "pipe", "ignore"],
  detached: true,
});
children.push(core);
const ready = await new Promise((resolveReady, reject) => {
  let buf = "";
  core.stdout.on("data", (d) => {
    buf += String(d);
    const line = buf.split("\n").find((l) => l.startsWith("PENTEOS_READY "));
    if (line) resolveReady(JSON.parse(line.slice("PENTEOS_READY ".length)));
  });
  setTimeout(() => reject(new Error("the core did not start")), 30000);
});
const api = async (op, input, token = ready.token) => {
  const r = await fetch(`http://127.0.0.1:${ready.port}/v0/ops/${op}`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(input) });
  const body = await r.json();
  if (!body.ok) throw new Error(`${op}: ${body.error?.message}`);
  return body.result;
};

// 2. Some data, so the screens are not empty: scope, hosts, findings, a run, a batch.
await api("workspace.set_prefs", { onboarded: true, workStyle: "solo" });
await api("scope.add_rule", { rule: { effect: "include", target: { type: "cidr", value: "10.0.0.0/24" }, reason: L("red interna", "internal network") } });
await api("ingest.submit_batch", {
  batch: {
    format: "penteos.ingest/v0",
    source: { parser: "smoke@0.1", tool: "smoke" },
    rawIds: [],
    observedAt: new Date().toISOString(),
    items: [
      { op: "upsert", kind: "host", key: { ip: "10.0.0.5" }, attributes: { hostnames: ["db.corp.local"] }, confidence: 1 },
      { op: "upsert", kind: "host", key: { ip: "10.0.0.20" }, attributes: { hostnames: ["web.corp.local"] }, confidence: 1 },
    ],
  },
});
const f1 = await api("finding.create", { title: L("Panel de administración accesible sin autenticación", "Admin panel reachable without authentication"), severity: "high", description: L("El panel /admin responde 200 sin sesión.", "The /admin panel answers 200 without a session.") });
const f2 = await api("finding.create", { title: L("Cabeceras de seguridad ausentes", "Missing security headers"), severity: "low", description: L("Faltan CSP y HSTS.", "CSP and HSTS are missing.") });
// Something the tests left on the client's side: listed in the deliverable panel.
await api("trace.record", { what: L("La dirección prueba1@example.com quedó suscrita al boletín", "The address test1@example.com was left subscribed to the newsletter"), where: "POST http://10.0.0.20/api/subscribe", cleanup: L("Darla de baja desde el enlace del correo", "Unsubscribe it from the link in the email") }, ready.agentToken);
// How the run went: a note from the operator on what the agent missed.
await api("run_note.add", { kind: "missed", text: L("No probó el IDOR en /api/tenants/7", "It did not test the IDOR on /api/tenants/7") });
// What only the client can answer, gathered above the board.
await api("client_question.add", { text: L("¿Pueden darnos dos cuentas de prueba de clientes distintos para probar el aislamiento entre clientes?", "Can you give us two test accounts from different customers to test tenant isolation?"), path: L("Aislamiento entre clientes", "Tenant isolation") }, ready.agentToken);
await api("client_question.add", { text: L("¿Qué protege el portal que responde 403, y deberían estar publicados FTP y SSH en ese servidor?", "What does the portal answering 403 protect, and should FTP and SSH be exposed on that server?") }, ready.agentToken);
// The Maestro puts both up for approval: the findings card is part of what renders.
await api("finding.request_approval", { ids: [f1.id, f2.id], reason: L("Ambos tienen evidencia y remediación; el de cabeceras no pasó por el verificador.", "Both have evidence and remediation; the headers one did not go through the verifier.") }, ready.agentToken);
await api("engagement.update", { autonomy: "maestro_auto" });
// The code plugin: approved after "reviewing" its code, enabled here.
await api("plugin.approve", { id: "lab.panel", reviewedCode: true });
await api("plugin.set_project", { id: "lab.panel", engagementId: (await api("engagement.get", {})).id, enabled: true });
// The working plugin: approved, then enabled in this project.
await api("plugin.approve", { id: "lab.notes" });
await api("plugin.set_project", { id: "lab.notes", engagementId: (await api("engagement.get", {})).id, enabled: true });
await api("run.exec", { argv: ["echo", L("hola", "hello")], targets: [], risk: "passive", wait: 5 });
await api("task.create", { title: L("Definir niveles de seguridad y usuario de bajos privilegios", "Define security levels and a low-privilege user"), assignee: "operator", description: L("Necesito saber en qué niveles pruebo (low/medium/impossible) y si puedo usar gordonb/abc123 para control de acceso.", "I need to know which levels to test (low/medium/impossible) and whether I can use gordonb/abc123 for access control.") }, ready.agentToken);
await api("task.create", { title: L("Credenciales para el mapeo autenticado", "Credentials for the authenticated mapping"), assignee: "operator", priority: "high", question: L("¿Uso las credenciales por defecto del laboratorio o me pasás otras?", "Do I use the lab's default credentials or will you give me others?") }, ready.agentToken);
// A browsing request from the Maestro (something only a person at the browser can do).
await api("browser.request", { url: "http://10.0.0.20/login", title: L("Pasar el reto anti-bot y recorrer el login", "Pass the anti-bot challenge and walk through the login"), steps: [L("Abrir la página y esperar a que termine el reto", "Open the page and wait for the challenge to finish"), L("Probar un usuario inexistente", "Try a user that does not exist"), L("Recorrer el recupero de contraseña sin completarlo", "Walk through the password reset without completing it")] }, ready.agentToken);
// A card with what real agents write: a long URL, a long command and a code block.
await api(
  "task.create",
  {
    title: L("Confirmar acceso a https://plataforma.cliente-de-prueba.example/administracion/usuarios/listado?pagina=1&orden=desc", "Confirm access to https://platform.test-customer.example/administration/users/list?page=1&order=desc"),
    assignee: "operator",
    question: L("¿Puedo usar https://plataforma.cliente-de-prueba.example/api/v2/autenticacion/token?grant_type=client_credentials&scope=lectura_escritura_administracion para pedir el token?", "May I use https://platform.test-customer.example/api/v2/authentication/token?grant_type=client_credentials&scope=read_write_administration to request the token?"),
    description: L("Comando previsto:\n\n```\nsqlmap -u 'https://plataforma.cliente-de-prueba.example/turnos/buscar.php?especialidad=1&profesional=2' --batch --level=2 --risk=1 --random-agent\n```\n\nY revisar `X-Forwarded-For-Original-Client-Address-Header-Value`.", "Planned command:\n\n```\nsqlmap -u 'https://platform.test-customer.example/appointments/search.php?specialty=1&professional=2' --batch --level=2 --risk=1 --random-agent\n```\n\nAnd check `X-Forwarded-For-Original-Client-Address-Header-Value`."),
  },
  ready.agentToken,
);
await api("ingest.submit_batch", { batch: { format: "penteos.ingest/v0", source: { parser: "smoke@0.1", tool: "smoke" }, rawIds: [], observedAt: new Date().toISOString(), items: [{ op: "upsert", kind: "webapp", key: { origin: "http://10.0.0.20" }, confidence: 1 }, { op: "upsert", kind: "webapp", key: { origin: "https://10.0.0.5:8443" }, confidence: 1 }] } });
{
  const apps = await api("entity.query", { kind: "webapp" });
  const [a, b] = apps;
  for (const [app, category, status] of [[a, "INFO", "tested"], [a, "ATHN", "vulnerable"], [a, "SESS", "in_progress"], [a, "CRYP", "n/a"], [b, "INFO", "tested"], [b, "CONF", "vulnerable"]]) {
    await api("webapp.set_coverage", { webappId: app.id, category, status, note: "smoke" }, ready.agentToken);
  }
}
// 3. Vite, then Chrome.
const vite = spawn("npx", ["vite", "--port", "0", "--strictPort"], { cwd: join(root, "apps", "desktop"), stdio: ["ignore", "pipe", "ignore"], detached: true });
children.push(vite);
const viteUrl = await new Promise((resolveUrl, reject) => {
  vite.stdout.on("data", (d) => {
    const m = /Local:\s+(http:\/\/[^\s]+)/.exec(String(d));
    if (m) resolveUrl(m[1]);
  });
  setTimeout(() => reject(new Error("vite did not start")), 30000);
});
const url = `${viteUrl}?port=${ready.port}&token=${ready.token}&repo=${root}`;
const chrome = spawn(process.env.CHROME ?? "google-chrome", ["--headless=new", "--remote-debugging-port=9334", `--window-size=${W},${H}`, "--no-sandbox", "--disable-gpu", "about:blank"], { stdio: "ignore", detached: true });
children.push(chrome);
await sleep(1500);
const targets = await (await fetch("http://127.0.0.1:9334/json")).json();
const ws = new WebSocket(targets.find((t) => t.type === "page").webSocketDebuggerUrl);
await new Promise((r) => ws.on("open", r));
let id = 0;
const pending = new Map();
const errors = [];
ws.on("message", (m) => {
  const msg = JSON.parse(String(m));
  if (msg.id && pending.has(msg.id)) pending.get(msg.id)(msg), pending.delete(msg.id);
  if (msg.method === "Runtime.exceptionThrown") errors.push(msg.params.exceptionDetails?.exception?.description ?? "exception");
  if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "error") errors.push(msg.params.args.map((a) => a.value ?? a.description).join(" "));
  // A key missing from the catalog shows up as the raw key on screen.
  if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "warning" && String(msg.params.args[0]?.value ?? "").startsWith("[i18n]")) errors.push(String(msg.params.args[0].value));
});
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const evaluate = async (expression) => (await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true })).result?.result?.value;
await send("Page.enable");
await send("Runtime.enable");
await send("Emulation.setDeviceMetricsOverride", { width: W, height: H, deviceScaleFactor: 1, mobile: false });
await send("Page.addScriptToEvaluateOnNewDocument", { source: `try { localStorage.setItem("penteos.lang", ${JSON.stringify(LANG)}) } catch {}` });
await send("Page.navigate", { url });
// The splash, before the core answers (it fades out once connected).
await sleep(350);
writeFileSync(join(out, "splash.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
await sleep(3650);

let failed = 0;
// The plugin that crashed the previous start: disabled on its own, and the operator is told why.
{
  const notice = await evaluate(`(() => { const n = document.querySelector('.plugin-notice'); return n ? n.textContent : ""; })()`);
  const expected = LANG === "en" ? "stopped while it was activating" : "se detuvo mientras se activaba";
  const ok = notice.includes("Shodan (lab)") && notice.includes(expected);
  writeFileSync(join(out, "plugin-notices.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  await evaluate(`document.querySelector('.plugin-notices')?.closest('.modal')?.querySelector('.modal-f .btn.primary')?.click()`);
  await sleep(400);
  const closed = await evaluate(`!document.querySelector('.plugin-notices')`);
  if (!ok || !closed) failed++;
  console.log(`${ok && closed ? "ok " : "FAIL"} plugin crash at start: notice ${ok ? "shown" : `missing (${notice || "none"})`}, ${closed ? "dismissed" : "still open"}`);
}

// The first run of the session brings up the Executions tab (once).
{
  await api("run.exec", { argv: ["echo", L("primera", "first")], targets: [], risk: "passive", wait: 5 });
  await sleep(1200);
  const tab = await evaluate(`document.querySelector('.bottom .tab-btn.on')?.textContent ?? ""`);
  const expected = LANG === "en" ? "Runs" : "Ejecuciones";
  const ok = tab.includes(expected);
  if (!ok) failed++;
  console.log(`${ok ? "ok " : "FAIL"} first run opens ${expected} (${tab || "panel closed"})`);
}

// A run in progress shows on the Executions tab, and its cancel button really stops it.
{
  const long = await api("run.exec", { argv: ["sh", "-c", "trap '' INT; sleep 60"], targets: [], risk: "passive" });
  await sleep(1500);
  const spinning = await evaluate(`Boolean(document.querySelector('.bottom .tab-btn .tab-running'))`);
  await evaluate(`document.querySelector('.bottom .run-cancel')?.click()`);
  await sleep(4500);
  const after = await api("run.get", { runId: long.runId });
  const ok = spinning && after.status === "cancelled";
  if (!ok) failed++;
  console.log(`${ok ? "ok " : "FAIL"} running run: tab indicator ${spinning ? "shown" : "missing"}, cancel → ${after.status}`);
}

/** Letters and words that only Spanish text has (accents, ñ, opening marks, frequent words). */
const SPANISH = /[áéíóúñ¿¡]|\b(?:los|las|del|para|hallazgos?|fases?|alcance|tareas?|sin|con|una|que)\b/i;
const ENGLISH_ONLY = new Set(["home", "coverage", "findings", "board", "scope", "web", "report", "tools", "hosts", "services"]);
const sections = ["home", "coverage", "findings", "scope", "team", "board", "proxy", "web", "report", "hosts", "services", "domains", "tools", "memory", "notes", "secrets", "evolution", "metrics"];
for (const section of sections) {
  await evaluate(`__penteos.workbench.openPanel(${JSON.stringify(section)})`);
  await sleep(900);
  const ok = await evaluate(`Boolean(document.querySelector('.dv-active-tab') && document.querySelector('.panel, .home, .report'))`);
  const shot = await send("Page.captureScreenshot", { format: "png" });
  writeFileSync(join(out, `${section}.png`), Buffer.from(shot.result.data, "base64"));
  if (!ok) failed++;
  console.log(`${ok ? "ok " : "FAIL"} ${section}`);
  // English is the default language: the main screens must not leak Spanish text.
  if (LANG === "en" && ENGLISH_ONLY.has(section)) {
    const text = await evaluate(`document.body.innerText`);
    const leaks = [...new Set(String(text).split("\n").filter((l) => SPANISH.test(l)).map((l) => l.trim().slice(0, 80)))];
    if (leaks.length) failed++;
    console.log(`${leaks.length ? "FAIL" : "ok "} ${section}: no Spanish text${leaks.length ? ` - ${leaks.slice(0, 5).join(" | ")}` : ""}`);
  }
}
// Plugins: the section lists both (the crashed one off, the working one active and enabled
// here); an operation runs from its generated form; an entity menu opens prefilled from the host.
{
  const setValue = (selector, value) => `(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return false; const proto = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(proto, "value").set.call(el, ${JSON.stringify(value)}); el.dispatchEvent(new Event("input", { bubbles: true })); return true; })()`;
  await evaluate(`__penteos.workbench.openPanel("plugins")`);
  await sleep(1200);
  const cards = await evaluate(`[...document.querySelectorAll('.plugin-card')].map((c) => c.textContent)`);
  writeFileSync(join(out, "plugins.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  const listed = cards.length >= 2 && cards.some((c) => c.includes("Notas de campo (lab)")) && cards.some((c) => c.includes("Shodan (lab)"));
  if (!listed) failed++;
  console.log(`${listed ? "ok " : "FAIL"} plugins: section lists ${cards.length} plugin(s)`);

  // From the section: run "Anotar host" with its form.
  await evaluate(`[...document.querySelectorAll('.plugin-op')].find((o) => /Anotar host|Annotate host/.test(o.textContent))?.querySelector('button')?.click()`);
  await sleep(500);
  const filled = (await evaluate(setValue("#pf-ip", "10.0.0.5"))) && (await evaluate(setValue("#pf-note", "SSH con banner viejo")));
  await evaluate(`document.querySelector('.pf')?.closest('.modal')?.querySelector('.modal-f .btn.primary')?.click()`);
  await sleep(1500);
  const message = await evaluate(`document.querySelector('.pf-message')?.textContent ?? document.querySelector('.pf-error')?.textContent ?? ""`);
  writeFileSync(join(out, "plugin-run.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  const ran = filled && message.includes("10.0.0.5: SSH con banner viejo");
  if (!ran) failed++;
  console.log(`${ran ? "ok " : "FAIL"} plugins: operation ran from its form (${message || "no result"})`);
  await evaluate(`document.querySelector('.pf')?.closest('.modal')?.querySelector('.modal-f .btn.ghost')?.click()`);
  await sleep(300);

  // The annotation is on the host, and the host's detail offers the plugin's menu, prefilled.
  const host = (await api("entity.query", { kind: "host", text: "10.0.0.5" }))[0];
  const ext = (await api("entity.get", { id: host.id })).ext?.["lab.notes"]?.note;
  await evaluate(`__penteos.workbench.openEntity(${JSON.stringify(host.id)}, "10.0.0.5")`);
  await sleep(1200);
  const shown = await evaluate(`document.querySelector('.panel-scroll')?.textContent?.includes("SSH con banner viejo") ?? false`);
  await evaluate(`[...document.querySelectorAll('.detail-head .btn')].find((b) => /Anotar|Annotate/.test(b.textContent))?.click()`);
  await sleep(900);
  const prefilled = await evaluate(`document.querySelector('#pf-ip')?.value ?? ""`);
  writeFileSync(join(out, "plugin-entity-menu.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  await evaluate(`document.querySelector('.pf')?.closest('.modal')?.querySelector('.modal-f .btn.ghost')?.click()`);
  const okMenu = ext === "SSH con banner viejo" && shown && prefilled === "10.0.0.5";
  if (!okMenu) failed++;
  console.log(`${okMenu ? "ok " : "FAIL"} plugins: annotation on the host (${ext ?? "none"}), shown ${shown}, entity menu prefilled (${prefilled || "empty"})`);

  // New project with plugins installed: the last step offers them, each description in one
  // language (a description written in both once blanked the whole window here).
  await evaluate(`window.dispatchEvent(new KeyboardEvent('keydown', { key: 'n', ctrlKey: true }))`);
  await sleep(500);
  await evaluate(`document.querySelector('.wizard .choice')?.click()`);
  await sleep(300);
  const inputs = await evaluate(`(() => { const els = [...document.querySelectorAll('.wizard input.input')]; const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set; [["https://www.lab.example/login", 0], ["Wizard smoke", 1]].forEach(([v, i]) => { if (els[i]) { set.call(els[i], v); els[i].dispatchEvent(new Event("input", { bubbles: true })); } }); return els.length; })()`);
  await sleep(100);
  // A URL pasted as the client becomes the site's name, and the empty scope gets it.
  await evaluate(`document.querySelectorAll('.wizard input.input')[0]?.dispatchEvent(new FocusEvent("focusout", { bubbles: true }))`);
  await sleep(200);
  const named = await evaluate(`({ client: document.querySelectorAll('.wizard input.input')[0]?.value, scope: document.querySelector('.wizard textarea')?.value })`);
  const okNamed = named.client === "lab.example" && named.scope === "https://www.lab.example";
  if (!okNamed) failed++;
  console.log(`${okNamed ? "ok " : "FAIL"} new project: a URL as the client becomes "${named.client}", scope "${named.scope}"`);
  await evaluate(`document.querySelector('.wizard .btn.primary')?.click()`);
  await sleep(800);
  const wizardPlugins = await evaluate(`[...document.querySelectorAll('.wizard-plugin')].map((p) => p.textContent)`);
  const rendered = await evaluate(`Boolean(document.querySelector('.wizard-card')) && !document.querySelector('.error-boundary')`);
  writeFileSync(join(out, "wizard-plugins.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  const panelText = wizardPlugins.find((p) => p.includes("Panel (lab)")) ?? "";
  const oneLanguage = /Plugin de código de laboratorio con paneles\.|Lab code plugin with panels\./.test(panelText) && !(panelText.includes("Plugin de código") && panelText.includes("Lab code plugin"));
  const okWizard = inputs >= 2 && rendered && oneLanguage;
  if (!okWizard) failed++;
  console.log(`${okWizard ? "ok " : "FAIL"} new project: plugins step ${rendered ? "rendered" : "blank"}, ${wizardPlugins.length} plugin(s) offered, description ${oneLanguage ? "in one language" : `wrong (${panelText || "missing"})`}`);
  await evaluate(`window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))`);
  await sleep(300);
}
// Help, About Penteos: the author, a way to reach them, and where the project lives.
{
  await evaluate(`[...document.querySelectorAll('.menu-title')].find((b) => /^(Ayuda|Help)$/.test(b.textContent.trim()))?.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }))`);
  await sleep(200);
  await evaluate(`[...document.querySelectorAll('.menu-item')].find((x) => /Acerca de|About/.test(x.textContent))?.click()`);
  await sleep(400);
  const about = await evaluate(`document.querySelector('.about')?.textContent ?? ""`);
  writeFileSync(join(out, "about.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  const okAbout = /Santiago Habib/.test(about) && /santiago@kalir\.io/.test(about) && /AGPL-3\.0/.test(about);
  if (!okAbout) failed++;
  console.log(`${okAbout ? "ok " : "FAIL"} about: author, contact and license shown`);
  await evaluate(`window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))`);
  await sleep(200);
}
// The catalog: the ready-made plugins are offered; Jira installs from the interface with one
// approval, and once enabled in the project its action shows on a finding.
{
  await evaluate(`__penteos.workbench.openPanel("plugins")`);
  await sleep(1000);
  const offers = await evaluate(`[...document.querySelectorAll('.plugin-offer b')].map((b) => b.textContent)`);
  writeFileSync(join(out, "plugins-catalog.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  await evaluate(`[...document.querySelectorAll('.plugin-offer')].find((o) => o.querySelector('b')?.textContent === "Jira")?.querySelector('button')?.click()`);
  await sleep(500);
  await evaluate(`document.querySelector('.modal .plugin-perms')?.closest('.modal')?.querySelector('.modal-f .btn.primary')?.click()`);
  await sleep(1500);
  const jira = (await api("plugin.list", {})).plugins.find((p) => p.id === "penteos.jira");
  await api("plugin.set_project", { id: "penteos.jira", engagementId: (await api("engagement.get", {})).id, enabled: true });
  await evaluate(`__penteos.workbench.openFinding(${JSON.stringify(f1.id)}, "f1")`);
  await sleep(1300);
  const action = await evaluate(`[...document.querySelectorAll('.workflow .btn')].some((b) => /Exportar a Jira|Export to Jira/.test(b.textContent))`);
  writeFileSync(join(out, "plugin-finding-action.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  const ok = ["Jira", "Proveedores de IA", "Shodan", "Slack"].every((n) => offers.includes(n)) && jira?.status === "active" && action;
  if (!ok) failed++;
  console.log(`${ok ? "ok " : "FAIL"} plugins: catalog offers ${offers.length}, Jira installed from the UI (${jira?.status ?? "missing"}), action on a finding ${action ? "shown" : "missing"}`);
}
// The Maestro builds a plugin: draft, sandbox test with a recorded response, proposal; the
// card shows in the conversation and the operator installs it with one click.
{
  const agentApi = (op, input) => api(op, input, ready.agentToken);
  const draft = {
    id: "maestro.status-page",
    name: "Status page",
    version: "0.1.0",
    description: { es: "Cuenta los hosts relevados del proyecto.", en: "Counts the project's hosts." },
    permissions: ["graph:read"],
    contributes: {
      operations: [{
        name: "check",
        title: { es: "Ver estado", en: "Check status" },
        description: "How many hosts the project has.",
        steps: [{ do: "graph_query", id: "h", kind: "host" }],
        result: { status: "{{steps.h | length}} hosts" },
        view: { type: "message", text: "{{result.status}}" },
      }],
    },
  };
  await agentApi("plugin.draft_write", { manifest: draft });
  // An agent reads results as the model would: text (masked), not an object.
  const testText = await agentApi("plugin.draft_test", { id: "maestro.status-page", operation: "check", fixtures: { hosts: ["10.0.0.1", "10.0.0.2"] }, expect: { contains: ["2 hosts"] } });
  const test = { ok: /"ok":\s*true/.test(String(testText)), error: String(testText).slice(0, 200) };
  await agentApi("plugin.draft_propose", { id: "maestro.status-page", reason: "Para ver de un vistazo cuántos hosts hay", evidence: "Probado con dos hosts de prueba: devolvió «2 hosts»." });
  await evaluate(`__penteos.workbench.openPanel("plugins")`);
  await sleep(1500);
  const card = await evaluate(`Boolean(document.querySelector('.plugin-proposal'))`);
  const draftShown = await evaluate(`[...document.querySelectorAll('.plugin-draft b')].some((b) => b.textContent === "Status page")`);
  writeFileSync(join(out, "plugin-proposal.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  await evaluate(`document.querySelector('.plugin-proposal')?.closest('.approval-card')?.querySelector('.actions .btn.primary')?.click()`);
  await sleep(2000);
  const installed = (await api("plugin.list", {})).plugins.find((p) => p.id === "maestro.status-page");
  const ok = test.ok && card && draftShown && installed?.status === "active";
  if (!ok) failed++;
  console.log(`${ok ? "ok " : "FAIL"} plugins: the Maestro built one (test ${test.ok ? "passed" : test.error}), card ${card ? "shown" : "missing"}, draft ${draftShown ? "listed" : "missing"}, installed ${installed?.status ?? "no"}`);
}
// Code plugin panels: in a tab and inside a host's detail, isolated, network blocked, bridge working.
{
  await evaluate(`__penteos.workbench.openPluginPanel("lab.panel", "main", "Panel de prueba")`);
  await sleep(2500);
  writeFileSync(join(out, "plugin-panel.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  const host = (await api("entity.query", { kind: "host", text: "10.0.0.20" }))[0];
  await evaluate(`__penteos.workbench.openEntity(${JSON.stringify(host.id)}, "10.0.0.20")`);
  await sleep(2500);
  writeFileSync(join(out, "plugin-panel-entity.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  const marks = await api("entity.query", { kind: "lab.panel:mark" });
  const tab = marks.find((m) => m.attributes.note === "from-panel-tab");
  const entity = marks.find((m) => m.attributes.note === "from-panel-entity");
  const frames = await evaluate(`[...document.querySelectorAll('iframe.plugin-frame')].map((f) => f.getAttribute("sandbox"))`);
  const card = (await api("plugin.list", {})).plugins.find((p) => p.id === "lab.panel");
  const ok = Boolean(tab && entity) && tab.attributes.fetchBlocked === true && entity.attributes.fetchBlocked === true && frames.length > 0 && frames.every((x) => x === "allow-scripts") && card?.status === "active";
  if (!ok) failed++;
  console.log(`${ok ? "ok " : "FAIL"} plugins: code panel in a tab (${tab ? `network ${tab.attributes.fetchBlocked ? "blocked" : "OPEN"}` : "no call"}) and in a host (${entity ? "called" : "no call"}), frames ${JSON.stringify(frames)}, isolation ${card?.isolation ?? "?"}`);
}
// Extensions: the project's plugins bring panels and actions → their own place in the activity bar.
{
  const label = LANG === "en" ? "Extensions" : "Extensiones";
  const hasPlace = await evaluate(`Boolean(document.querySelector('.ab-btn[aria-label^="${label}"]'))`);
  await evaluate(`document.querySelector('.ab-btn[aria-label^="${label}"]')?.click()`);
  await sleep(1500);
  const hub = await evaluate(`(() => { const h = document.querySelector('.plugin-hub'); return h ? { actions: h.querySelectorAll('.plugin-hub-actions .btn').length, frame: Boolean(h.querySelector('iframe.plugin-frame')) } : null; })()`);
  writeFileSync(join(out, "plugin-extensions.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  const ok = hasPlace && hub && hub.actions > 0 && hub.frame;
  if (!ok) failed++;
  console.log(`${ok ? "ok " : "FAIL"} plugins: Extensions place ${hasPlace ? "shown" : "missing"}, ${hub ? `${hub.actions} actions, panel ${hub.frame ? "embedded" : "missing"}` : "no hub"}`);
}
// Clicking a group in the activity bar lands on its PRIMARY tab, not the last sub-tab you had open.
{
  await evaluate(`__penteos.workbench.openPanel("coverage")`); // deep link to a sub-tab
  await sleep(500);
  await evaluate(`__penteos.workbench.openPanel("findingsGroup")`); // activity-bar click on the group
  await sleep(500);
  const primary = await evaluate(`(() => { const on = document.querySelector('.group-tab.on'); const first = document.querySelector('.group-tab'); return Boolean(on) && on === first; })()`);
  if (!primary) failed++;
  console.log(`${primary ? "ok " : "FAIL"} nav: group opens on its primary tab`);
}
// Nothing inside a board card may stick out of it (long URLs, commands, code).
{
  await evaluate(`__penteos.workbench.openPanel("board")`);
  await sleep(900);
  const overflow = await evaluate(`(() => {
    const out = [];
    for (const card of document.querySelectorAll('.board .card')) {
      const box = card.getBoundingClientRect();
      for (const el of card.querySelectorAll('*')) {
        const r = el.getBoundingClientRect();
        if (r.width && (r.right > box.right + 1 || r.left < box.left - 1)) out.push(el.className || el.tagName);
        // Text that does not fit its own box (a text node is not an element, so check the parent).
        if (el.scrollWidth > el.clientWidth + 1 && getComputedStyle(el).overflowX === "visible" && el.clientWidth) out.push((el.className || el.tagName) + " text");
      }
      if (card.scrollWidth > card.clientWidth + 1) out.push('card scrolls');
    }
    return [...new Set(out)].slice(0, 8);
  })()`);
  if (overflow.length) failed++;
  console.log(`${overflow.length ? "FAIL" : "ok "} board cards keep their content inside${overflow.length ? `: ${overflow.join(", ")}` : ""}`);
}
// Generating the report shows the document (it used to crash the whole window: black screen).
{
  await evaluate(`__penteos.workbench.openPanel("report")`);
  await sleep(900);
  // The three steps: Prepare (with its fixes), then Generate → Preview.
  writeFileSync(join(out, "report-prepare.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  await evaluate(`[...document.querySelectorAll('.report-step')].find((b) => /Generar|Generate/.test(b.textContent))?.click()`);
  await sleep(600);
  await evaluate(`[...document.querySelectorAll('.report-actions button')].find((b) => /Vista previa|Preview/.test(b.textContent))?.click()`);
  await sleep(2500);
  const ok = await evaluate(`Boolean(document.querySelector('.report-paper')) && !document.querySelector('.error-boundary') && Boolean(document.querySelector('.topbar'))`);
  writeFileSync(join(out, "report-generated.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  if (!ok) failed++;
  console.log(`${ok ? "ok " : "FAIL"} generating the report shows the document`);
}
// The Maestro's panel up close (cards, waiting strip, composer), at 2x.
{
  await evaluate(`__penteos.workbench.openPanel("home")`);
  await sleep(800);
  const r = await evaluate(`(() => { const x = document.querySelector('.agentbar').getBoundingClientRect(); return { x: x.x, y: x.y, width: x.width, height: x.height }; })()`);
  const shot = await send("Page.captureScreenshot", { format: "png", clip: { ...r, scale: 2 } });
  writeFileSync(join(out, "agent.png"), Buffer.from(shot.result.data, "base64"));
  // The model picker: the ChatGPT plan first, then its sign-in.
  await evaluate(`document.querySelector('.pp-btn')?.click()`);
  await sleep(500);
  const groups = await evaluate(`[...document.querySelectorAll('.pp-menu .pp-group')].map((g) => g.textContent)`);
  writeFileSync(join(out, "provider-picker.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  await evaluate(`[...document.querySelectorAll('.pp-opt')].find((o) => /ChatGPT/.test(o.textContent))?.querySelector('.icon-btn')?.click()`);
  await sleep(700);
  const signIn = await evaluate(`Boolean(document.querySelector('[data-oai-siwc-button]'))`);
  writeFileSync(join(out, "provider-chatgpt.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  await evaluate(`window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))`);
  await sleep(300);
  const pickerOk = Array.isArray(groups) && /plan/i.test(groups[0] ?? "") && signIn;
  if (!pickerOk) failed++;
  console.log(`${pickerOk ? "ok " : "FAIL"} model picker: the ChatGPT plan first, its sign-in button in settings`);
}
// The activity bar tooltip of the board, hovered.
{
  await evaluate(`__penteos.workbench.openPanel("board")`);
  await sleep(800);
  const r = await evaluate(`(() => { const b = document.querySelector('.ab-btn[aria-label^="${LANG === "en" ? "Board" : "Tablero"}"]'); const x = b.getBoundingClientRect(); return { x: x.x + x.width / 2, y: x.y + x.height / 2 }; })()`);
  await send("Input.dispatchMouseEvent", { type: "mouseMoved", x: r.x, y: r.y });
  await sleep(500);
  writeFileSync(join(out, "tooltip.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  await send("Input.dispatchMouseEvent", { type: "mouseMoved", x: 800, y: 500 });
  // A card hovered (edit and delete show up), then its editor.
  const c = await evaluate(`(() => { const x = document.querySelector('.board .card').getBoundingClientRect(); return { x: x.x + 40, y: x.y + 20 }; })()`);
  await send("Input.dispatchMouseEvent", { type: "mouseMoved", x: c.x, y: c.y });
  await sleep(300);
  writeFileSync(join(out, "card-hover.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  await evaluate(`document.querySelector('.board .card .card-actions button').click()`);
  await sleep(500);
  writeFileSync(join(out, "card-edit.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
  await evaluate(`window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))`);
  await sleep(300);
}
await evaluate(`window.dispatchEvent(new KeyboardEvent('keydown',{key:'n',ctrlKey:true,bubbles:true}))`);
await sleep(800);
writeFileSync(join(out, "wizard.png"), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).result.data, "base64"));
ws.close();
const real = errors.filter((e) => !/WebSocket|net::|Failed to load resource/.test(e));
if (real.length) {
  console.error("console errors:");
  for (const e of real) console.error("  " + e);
}
console.log(`${sections.length - failed}/${sections.length} sections rendered · screenshots in ${out}`);
process.exit(failed || real.length ? 1 : 0);
