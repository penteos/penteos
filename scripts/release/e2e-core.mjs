// The core of an installed Penteos, end to end, on a clean data folder:
// project, scope, finding, catalog plugins (declarative, Node code, Python), reports, export.
//   ELECTRON_RUN_AS_NODE=1 /opt/Penteos/penteos scripts/release/e2e-core.mjs /opt/Penteos [--offline]
//   ELECTRON_RUN_AS_NODE=1 ~/Applications/Penteos.app/Contents/MacOS/Penteos scripts/release/e2e-core.mjs ~/Applications/Penteos.app
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
// The installed app's folder (/opt/Penteos, an extracted AppImage…): its own Electron runs the core.
const app = process.argv[2] ?? "/opt/Penteos";
const online = !process.argv.includes("--offline");
// --tools: the tool box from the verified catalog (needs internet; run it as a normal user).
const withTools = process.argv.includes("--tools");
// --only-tools: just that part (the matrix runs it again as a user without privileges).
const onlyTools = process.argv.includes("--only-tools");
const data = mkdtempSync(join(tmpdir(), "penteos-pkg-"));
// The agents' browser is the app itself in its agent-browser mode, as the desktop app sets it up
// (PENTEOS_E2E_BROWSER_ARGS: extra flags for the test environment, e.g. --no-sandbox as root).
const browserArgs = (process.env.PENTEOS_E2E_BROWSER_ARGS ?? "").split(" ").filter(Boolean);
// Linux: <app>/penteos and <app>/resources. macOS: Penteos.app/Contents/MacOS/Penteos and Contents/Resources.
const mac = app.endsWith(".app");
const bin = mac ? join(app, "Contents/MacOS/Penteos") : join(app, "penteos");
const resources = mac ? join(app, "Contents/Resources") : join(app, "resources");
const env = { ...process.env, ELECTRON_RUN_AS_NODE: "1", PENTEOS_AGENT_BROWSER: JSON.stringify({ command: bin, args: browserArgs }) };
const core = spawn(bin, [join(resources, "core/core.mjs"), "--data-dir", data], { cwd: join(resources, "core"), env, stdio: ["ignore", "pipe", "pipe"] });
let err = "";
core.stderr.on("data", (d) => (err += d));
const ready = await new Promise((res, rej) => {
  let buf = "";
  core.stdout.on("data", (d) => { buf += d; const m = /PENTEOS_READY (.*)\n/.exec(buf); if (m) res(JSON.parse(m[1])); });
  core.on("exit", (c) => rej(new Error(`core exited ${c}: ${err.slice(-1500)}`)));
  setTimeout(() => rej(new Error("no READY in 60s: " + err.slice(-1500))), 60000);
});
const results = [];
const api = async (op, input = {}, token = ready.token) => {
  const r = await fetch(`http://127.0.0.1:${ready.port}/v0/ops/${op}`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(input) });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${op} → ${r.status} ${JSON.stringify(body).slice(0, 400)}`);
  return body.result ?? body;
};
const step = async (name, fn) => { try { const out = await fn(); results.push(["ok", name, out ?? ""]); return out; } catch (e) { results.push(["FAIL", name, String(e.message ?? e).slice(0, 500)]); } };
try {
  const eng = await step("create project", async () => (await api("engagement.create", { clientName: "Acme", name: "Package test", mode: "web" })));
  const engagementId = eng?.id ?? eng?.engagement?.id;
  await step("activate project", () => api("engagement.activate", { id: engagementId }).catch(() => "no activate op"));
  await step("scope rule", () => api("scope.add_rule", { engagementId, rule: { effect: "include", target: { type: "domain", value: "acme.test" } } }));
  if (!onlyTools) {
    const f = await step("create finding", () => api("finding.create", { engagementId, title: "SQL injection", severity: "high", description: "d", remediation: "r", reproduction: "1. step" }));
    await step("approve finding", () => api("finding.set_status", { engagementId, id: f?.id, status: "approved" }));
    for (const id of ["penteos.word-report", "penteos.passive-scan", "penteos.excel", "penteos.jwt"]) {
      await step(`install ${id}`, async () => (await api("plugin.install", { id })).plugin?.status);
      await step(`enable ${id}`, () => api("plugin.set_project", { id, engagementId, enabled: true }).then(() => "ok"));
    }
    await step("active plugins", async () => (await api("plugin.list")).plugins.map((p) => `${p.id}:${p.status}${p.reason ? "(" + (p.reason.code ?? "") + " " + (p.reason.detail ?? "").slice(0, 120) + ")" : ""}`).join(" "));
    await step("declarative plugin (Word)", async () => (await api("plugin.run", { engagementId, name: "plugin.penteos.word-report.generate", input: { author: "Ana" } })).files?.map((x) => x.name));
    await step("Node plugin (passive scanner)", async () => JSON.stringify((await api("plugin.run", { engagementId, name: "plugin.penteos.passive-scan.summary", input: {} })).result).slice(0, 80));
    await step("Node plugin with a panel (JWT)", async () => JSON.stringify((await api("plugin.run", { engagementId, name: "plugin.penteos.jwt.inspect", input: { token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.cThIIoDvwdueQB468K5xDc5633seEFoqwxjF_xSJyQQ" } })).result).slice(0, 100));
    await step("Python plugin (Excel)", async () => (await api("plugin.run", { engagementId, name: "plugin.penteos.excel.excel", input: {} })).files?.map((x) => x.name));
    await step("HTML report", async () => (await api("report.render", { engagementId, format: "html" })).html.length + " bytes");
    await step("Word report", async () => (await api("report.render", { engagementId, format: "docx" })).docxBase64.length + " b64");
    await step("executive report", async () => (await api("report.render", { engagementId, format: "markdown", kind: "executive" })).markdown.split("\n")[0]);
    await step("versions", async () => (await api("report.versions", { engagementId })).versions.length);
    if (online) await step("web search (Parallel)", async () => (await api("research.search", { engagementId, objective: "Apache Log4Shell advisory", queries: ["CVE-2021-44228 advisory"] })).results.length + " results");
    await step("plugins after a rescan", async () => { await api("plugin.rescan"); return (await api("plugin.list")).plugins.map((p) => p.id + ":" + p.status).join(" "); });
    await step("Maestro's browser (Penteos's Chromium)", async () => {
      const { createServer } = await import("node:http");
      const site = createServer((_q, s) => {
        s.setHeader("content-type", "text/html");
        s.end("<title>Lab</title><div id=x></div><script>document.getElementById('x').textContent='rendered by JavaScript'</script>");
      });
      await new Promise((r) => site.listen(0, "127.0.0.1", r));
      const port = site.address().port;
      try {
        await api("scope.add_rule", { engagementId, rule: { effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) } });
        const r = await api("browser.open", { engagementId, url: `http://127.0.0.1:${port}/` });
        if (!JSON.stringify(r).includes("rendered by JavaScript")) throw new Error(`the page's JavaScript did not run: ${JSON.stringify(r).slice(0, 200)}`);
        return "opened the page and ran its JavaScript";
      } finally {
        site.close();
      }
    });
  }
  if (!onlyTools) await step("export project", async () => (await api("project.export", { engagementId, dest: join(data, "x.penteos") })).path);
  if (withTools || onlyTools) {
    const uid = typeof process.getuid === "function" ? process.getuid() : -1;
    const install = async (tool) => {
      const r = await api("tool.install", { engagementId, tool });
      if (!r.runId) throw new Error(`no install run: ${JSON.stringify(r).slice(0, 200)}`);
      const done = await api("run.wait", { engagementId, runId: r.runId, seconds: 600 });
      if (done.status !== "finished") throw new Error(`${tool}: ${done.status} ${JSON.stringify(done.summary ?? done).slice(0, 300)}`);
      const st = (await api("tool.list", { engagementId, refresh: true })).tools.find((t) => t.name === tool);
      if (!st?.installed || !st.managed) throw new Error(`${tool} not installed by Penteos: ${JSON.stringify(st).slice(0, 200)}`);
      return `${tool} ${st.version} (user ${uid === 0 ? "root" : uid})`;
    };
    await step("tools: ffuf from the catalog, no root", () => install("ffuf"));
    if (process.arch === "x64") await step("tools: official nmap from nmap.org, no root", () => install("nmap"));
    await step("tools: sqlmap with uv and its own Python, no root", () => install("sqlmap"));
    await step("port_scan capability (with the tool or the built-in method)", async () => {
      const { createServer } = await import("node:http");
      const site = createServer((_q, s) => s.end("<title>Lab</title>"));
      await new Promise((r) => site.listen(0, "127.0.0.1", r));
      const port = site.address().port;
      try {
        await api("scope.add_rule", { engagementId, rule: { effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) } }).catch(() => undefined);
        const r = await api("capability.run", { engagementId, capability: "port_scan", targets: [`127.0.0.1:${port}`], options: { preset: "quick" } });
        if (r.runId) await api("run.wait", { engagementId, runId: r.runId, seconds: 300 });
        const services = (await api("entity.query", { engagementId, kind: "service", limit: 50 })) ?? [];
        const list = Array.isArray(services) ? services : services.entities ?? [];
        return `${r.provider} (${r.quality}); services in the graph: ${list.length}`;
      } finally {
        site.close();
      }
    });
    await step("tool box", async () => {
      const b = await api("tool.toolbox", { engagementId });
      return `${b.tools.filter((t) => t.installed).map((t) => t.name).join(", ")} · ${(b.usage / 1e6).toFixed(0)} MB`;
    });
  }
} finally {
  core.kill("SIGTERM");
  for (const [s, n, o] of results) console.log(`${s.padEnd(4)} ${n}: ${typeof o === "string" ? o : JSON.stringify(o).slice(0, 200)}`);
  if (err.trim()) console.log("--- stderr:\n" + err.slice(-1500));
  setTimeout(() => rmSync(data, { recursive: true, force: true }), 500);
  // Any failed step fails the run: the matrix must not call a distribution good on the GUI alone.
  if (results.some(([s]) => s === "FAIL")) process.exitCode = 1;
}
