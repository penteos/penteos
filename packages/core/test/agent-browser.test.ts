import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterAll, beforeAll, expect, it } from "vitest";
import {
  AGENT_BROWSER_SOURCE,
  CertificateAuthority,
  closeAllBrowsers,
  interceptionHooks,
  Interceptor,
  configureAgentBrowser,
  DEFAULT_PROXY_SETTINGS,
  type Engagement,
  executeOperation,
  agentBrowserKind,
  type OperationContext,
  PenteosProxy,
  ToolRegistry,
  ToolRunner,
  Workspace,
} from "../src/index.js";

/**
 * The agents' browser end to end: a small JavaScript application behind Penteos's real proxy,
 * driven by a headless Chromium. Skipped where no Chromium is installed.
 */

const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
// Penteos's own Chromium (PENTEOS_AGENT_BROWSER, as the desktop app sets it) or the system's.
const chrome = agentBrowserKind() !== "none";
let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let proxy: PenteosProxy;
let site: Server;
let origin: string;

// A tiny app: the list only appears once its script runs, and a button asks for confirmation.
const PAGE = `<!doctype html><html><head><title>Inventario</title></head><body>
<ul id="items"></ul>
<form id="f"><input name="q"><button type="submit">Buscar</button></form>
<p id="out"></p>
<button id="del" type="button">Borrar todo</button>
<script>
fetch("/api/items").then((r) => r.json()).then((items) => {
  document.getElementById("items").innerHTML = items.map((i) => "<li>" + i + "</li>").join("");
});
document.getElementById("f").addEventListener("submit", (e) => {
  e.preventDefault();
  document.getElementById("out").textContent = "Resultados para " + new FormData(e.target).get("q");
});
document.getElementById("del").addEventListener("click", () => confirm("Seguro?"));
</script></body></html>`;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-browser-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Browser", mode: "web" }, agent);
  site = createServer((req, res) => {
    if (req.url === "/api/items") {
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify(["tornillos", "tuercas"]));
    }
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(PAGE);
  });
  await new Promise<void>((r) => site.listen(0, "127.0.0.1", () => r()));
  const port = (site.address() as { port: number }).port;
  origin = `http://127.0.0.1:${port}`;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, agent);
  const ca = await CertificateAuthority.load(join(dir, "ca"));
  proxy = new PenteosProxy(ws, ca, { token: "t", actor: agent, settings: () => DEFAULT_PROXY_SETTINGS });
  // As in the app: interception wired in, and switched ON by the operator. The agents' browser must
  // still get through (a real run had it "dropped by the operator").
  proxy.hooks = interceptionHooks(new Interceptor(), AGENT_BROWSER_SOURCE);
  eng.setMeta("intercept", { requests: true, responses: true }, agent);
  await proxy.start(0);
  configureAgentBrowser({ port: proxy.port, token: "t" });
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
}, 30_000);

afterAll(async () => {
  closeAllBrowsers();
  await proxy?.close();
  site?.close();
  ws?.close();
  rmSync(dir, { recursive: true, force: true });
}, 30_000);

const ctx = (): OperationContext => ({
  workspace: ws,
  caller: { actor: agent, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } },
  defaultEngagementId: eng.info.id,
  engagement: () => eng,
  runner: () => runner,
});

type Done = { status: string; page: { title: string; text: string; forms: Array<{ fields: Array<{ name: string; selector: string }> }> }; requests: Array<{ url: string; status?: number }>; dialogs?: Array<{ type: string; message: string }>; screenshotRawId?: string };

it.skipIf(!chrome)("opens a JavaScript page through the proxy and sees what its code renders", async () => {
  const r = (await executeOperation("browser.open", { url: `${origin}/` }, ctx())) as Done;
  expect(r.status).toBe("done");
  expect(r.page.title).toBe("Inventario");
  expect(r.page.text).toContain("tornillos");
  expect(r.requests.some((q) => q.url.endsWith("/api/items") && q.status === 200)).toBe(true);
  // It went through the proxy, tagged as the agents' browser.
  const history = eng.queryProxy({ limit: 50 });
  expect(history.some((h) => h.url.endsWith("/api/items") && h.source === "agent")).toBe(true);
  // Nothing dropped, and none of Chrome's own housekeeping in the history.
  expect(history.filter((h) => h.blocked)).toEqual([]);
  expect(history.some((h) => /google/.test(h.url))).toBe(false);
}, 60_000);

it.skipIf(!chrome)("fills and submits a form, and reports the dialogs a click opens", async () => {
  const filled = (await executeOperation("browser.fill", { selector: "input[name=q]", value: "arandelas", submit: true }, ctx())) as Done;
  expect(filled.page.text).toContain("Resultados para arandelas");
  const clicked = (await executeOperation("browser.click", { text: "Borrar todo" }, ctx())) as Done;
  expect(clicked.dialogs).toEqual([{ type: "confirm", message: "Seguro?" }]);
}, 60_000);

it.skipIf(!chrome)("takes a screenshot as a raw artifact to cite as evidence", async () => {
  const r = (await executeOperation("browser.screenshot", {}, ctx())) as Done;
  expect(r.screenshotRawId).toMatch(/^sha256:/);
  const png = eng.readRaw(r.screenshotRawId!);
  expect(png.subarray(1, 4).toString()).toBe("PNG");
}, 60_000);

it.skipIf(!chrome)("refuses to open a page out of scope", async () => {
  await expect(executeOperation("browser.open", { url: "http://out-of-scope.test/" }, ctx())).rejects.toMatchObject({ code: "OUT_OF_SCOPE" });
});
