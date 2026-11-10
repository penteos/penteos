import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { createServer as createTcp, type Server as TcpServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Engagement, executeOperation, type OperationContext, renderReport, setPhase, Toolbox, type ToolCatalogEntry, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";
import { builtinCommonPaths, builtinCrawl, builtinHttpProbe, linksOf, productOf } from "../src/tools/builtins.js";

const human: Actor = { type: "human", id: "01JA0000000000000000000HMN" };
const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };

let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let web: Server;
let webPort: number;
let ssh: TcpServer;
let sshPort: number;
let catalogServer: Server;
/** What the fake download server sends for "nuclei" (a script that answers like nuclei). */
const fakeNuclei = new TextEncoder().encode('#!/bin/sh\nif [ "$1" = "-version" ]; then echo "Nuclei Engine Version: v3.11.1"; exit 0; fi\necho \'{"template-id":"fake","matched-at":"x"}\'\n');

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-cap-"));
  // A small site: a page with links, an admin page, robots.txt, and 404 for the rest.
  web = createServer((req, res) => {
    const pages: Record<string, [number, string, Record<string, string>?]> = {
      "/": [200, '<html><head><title>Tienda Acme</title><meta name="generator" content="WordPress 6.4"></head><body><a href="/productos">p</a><a href="/contacto">c</a><a href="https://otro.example/">x</a></body></html>', { server: "nginx/1.25.3", "x-powered-by": "PHP/8.2" }],
      "/productos": [200, '<a href="/productos/1">1</a>'],
      "/productos/1": [200, "uno"],
      "/contacto": [200, "contacto"],
      "/robots.txt": [200, "User-agent: *\nDisallow: /admin"],
      "/admin": [302, "", { location: "/login" }],
    };
    const p = pages[req.url ?? ""];
    if (!p) return void res.writeHead(404, { "content-type": "text/html" }).end("<h1>no existe</h1>");
    res.writeHead(p[0], { "content-type": "text/html", ...(p[2] ?? {}) });
    res.end(p[1]);
  });
  await new Promise<void>((r) => web.listen(0, "127.0.0.1", r));
  webPort = (web.address() as { port: number }).port;
  // A service that speaks first, like SSH.
  ssh = createTcp((s) => s.end("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"));
  await new Promise<void>((r) => ssh.listen(0, "127.0.0.1", r));
  sshPort = (ssh.address() as { port: number }).port;
  catalogServer = createServer((_q, s) => s.end(fakeNuclei));
  await new Promise<void>((r) => catalogServer.listen(0, "127.0.0.1", r));

  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ language: "es", clientName: "Lab", name: "Capacidades", mode: "web" }, human);
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" } }, human);
  const nucleiEntry: ToolCatalogEntry = {
    name: "nuclei",
    version: "3.11.1",
    via: "release",
    homepage: "https://example.test",
    license: "MIT",
    binary: "nuclei",
    assets: { "linux-x64": { url: `http://127.0.0.1:${(catalogServer.address() as { port: number }).port}/nuclei`, sha256: createHash("sha256").update(fakeNuclei).digest("hex"), size: fakeNuclei.length, format: "raw", bin: "nuclei" } },
  };
  const box = new Toolbox(join(dir, "toolbox"), { catalog: [nucleiEntry], platform: "linux-x64", allowHttp: true, retryDelayMs: 5 });
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools"), box));
  // As on a clean machine: none of the real tools is found (their binaries point nowhere).
  for (const m of runner.registry.all()) runner.registry.save({ ...m, binaries: [`/nonexistent/${m.name}`] });
});

afterEach(async () => {
  for (const r of eng.runs(50)) if (r.status === "running") await runner.waitForRun(r.id, 10);
  await Promise.all([web, ssh, catalogServer].map((s) => new Promise((r) => s.close(r))));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const ctx = (actor: Actor): OperationContext => ({
  workspace: ws,
  caller: { actor, policy: actor.type === "agent" ? { type: "agent", autonomy: "autonomous", maxRisk: "active" } : { type: "human" } },
  defaultEngagementId: eng.info.id,
  engagement: () => eng,
  runner: () => runner,
});
const run = (capability: string, targets: string[], actor = agent) => executeOperation("capability.run", { capability, targets, wait: 30 }, ctx(actor)) as Promise<Record<string, unknown>>;

describe("Penteos's own methods write what the tool would", () => {
  it("probes HTTP like httpx: status, title, server, technologies", async () => {
    const out = await builtinHttpProbe([`http://127.0.0.1:${webPort}`], () => {});
    const line = JSON.parse(out);
    expect(line).toMatchObject({ status_code: 200, title: "Tienda Acme", webserver: "nginx/1.25.3", host: "127.0.0.1" });
    expect(line.tech).toEqual(expect.arrayContaining(["PHP/8.2", "WordPress 6.4"]));
  });

  it("crawls the same origin only, and finds common paths without counting 404 look-alikes", async () => {
    const crawl = (await builtinCrawl([`http://127.0.0.1:${webPort}/`], () => {})).split("\n").map((l) => JSON.parse(l).request.endpoint);
    expect(crawl).toEqual(expect.arrayContaining([`http://127.0.0.1:${webPort}/productos`, `http://127.0.0.1:${webPort}/productos/1`]));
    expect(crawl.some((u: string) => u.includes("otro.example"))).toBe(false);
    const paths = (await builtinCommonPaths([`http://127.0.0.1:${webPort}`], () => {})).split("\n").map((l) => JSON.parse(l).request.endpoint);
    expect(paths.sort()).toEqual([`http://127.0.0.1:${webPort}/admin`, `http://127.0.0.1:${webPort}/robots.txt`]);
    expect(linksOf('<a href="/a#x">', "http://h/")).toEqual(["http://h/a"]);
  });

  it("reads products from banners the way nmap reports them", () => {
    expect(productOf("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")).toEqual({ product: "OpenSSH", version: "9.6p1" });
    expect(productOf("HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Ubuntu)\r\n")).toEqual({ product: "Apache", version: "2.4.58" });
  });
});

describe("capabilities: the agent is never stuck for lack of a tool", () => {
  it("no httpx: Penteos's own probe runs, lands in the graph, opens ONE gap and proposes httpx… (not in this catalog: no card)", async () => {
    const r = await run("http_probe", [`http://127.0.0.1:${webPort}`]);
    expect(r).toMatchObject({ capability: "http_probe", provider: "penteos:http-probe", quality: "degraded", status: "finished" });
    expect(String(r.how)).toMatch(/gap/);
    const app = eng.query({ kind: "webapp" })[0]!;
    expect(app.attributes).toMatchObject({ origin: `http://127.0.0.1:${webPort}`, title: "Tienda Acme" });
    // Asked again with another target: the same gap gathers it, not a second one.
    await run("http_probe", [`127.0.0.1:${webPort}`]);
    const gaps = ((await executeOperation("gap.list", { status: "open" }, ctx(agent))) as { gaps: Array<{ capability: string; targets: string[]; count: number; text: string }> }).gaps;
    expect(gaps).toHaveLength(1);
    expect(gaps[0]).toMatchObject({ capability: "http_probe", count: 2 });
    expect(gaps[0]!.targets).toHaveLength(2);
    expect(gaps[0]!.text).toMatch(/método propio/);
  });

  it("no nmap: a TCP connect scan of its own finds the service and its product, as nmap's parser records it", async () => {
    const r = await executeOperation("capability.run", { capability: "port_scan", targets: ["127.0.0.1"], options: {}, wait: 30 }, ctx(agent));
    expect(r).toMatchObject({ provider: "penteos:tcp-connect", quality: "degraded" });
    // The 100 common ports do not include the test's random one: scan it the way the runner does.
    const { builtinPortScan } = await import("../src/tools/builtins.js");
    const xml = await builtinPortScan(["127.0.0.1"], () => {}, { ports: [sshPort, webPort] });
    expect(xml).toContain(`portid="${sshPort}"`);
    expect(xml).toContain('product="OpenSSH" version="9.6p1"');
  });

  it("no nuclei and no way of its own: a gap, one install card, nothing retried - then installed → resumed by itself", async () => {
    const r = await run("vuln_templates", [`http://127.0.0.1:${webPort}`]);
    expect(r).toMatchObject({ provider: "none", quality: "blocked", status: "gap" });
    expect(String(r.note)).toMatch(/Do NOT retry/);
    const card = runner.listApprovals().find((a) => a.request.kind === "install")!;
    expect(card.summary).toMatch(/nuclei 3\.11\.1.*no root/);
    // Again: same gap, same card.
    await run("vuln_templates", [`http://127.0.0.1:${webPort}`]);
    expect(runner.listApprovals().filter((a) => a.request.kind === "install")).toHaveLength(1);

    // The phase card shows it; the report lists it if they go on without it.
    const resumed: Array<{ status: string; runId?: string }> = [];
    eng.events.on("change", (e: { type: string; status?: string; runId?: string }) => e.type === "gap.resumed" && resumed.push({ status: e.status!, ...(e.runId ? { runId: e.runId } : {}) }));
    await executeOperation("approval.approve", { approvalId: card.id }, ctx(human));
    const install = eng.runs(20).find((x) => x.tool === "penteos-toolbox")!;
    expect((await runner.waitForRun(install.id, 10))!.status).toBe("finished");
    // Resumed by itself, as the agent that asked, with the tool now installed.
    for (let i = 0; i < 50 && !resumed.length; i++) await new Promise((r) => setTimeout(r, 50));
    expect(resumed).toHaveLength(1);
    // nuclei is intrusive, above the agent's ceiling: resuming never skips that, it asks.
    expect(resumed[0]!.status).toBe("pending_approval");
    const listGapsNow = async () => ((await executeOperation("gap.list", {}, ctx(agent))) as { gaps: Array<{ status: string; resolvedRun?: string; approvalId?: string }> }).gaps;
    const waiting = (await listGapsNow())[0]!;
    expect(waiting.status).toBe("resolving");
    await executeOperation("approval.approve", { approvalId: waiting.approvalId! }, ctx(human));
    const nucleiRun = eng.runs(20).find((x) => x.tool === "nuclei")!;
    expect(nucleiRun).toMatchObject({ actor: agent });
    expect((await listGapsNow())[0]).toMatchObject({ status: "resolved", resolvedRun: nucleiRun.id });
  });

  it("a gap shows on the phase card; going on without it records who and why, and the report says so", async () => {
    await run("vuln_templates", [`http://127.0.0.1:${webPort}`]);
    const asked = (await executeOperation("phase.request", { to: "mapping", summary: "recon hecho" }, ctx(agent))) as { note?: string };
    expect(asked.note).toMatch(/Hueco de herramientas/);
    setPhase(eng, "mapping", human);
    const g = ((await executeOperation("gap.list", {}, ctx(agent))) as { gaps: Array<{ status: string; accepted?: { reason: string } }> }).gaps[0]!;
    expect(g).toMatchObject({ status: "accepted", accepted: { reason: "Se pasó a «Mapeo» sin resolverlo" } });
    expect(renderReport(eng)).toMatch(/Pruebas que no se pudieron completar por falta de herramientas[\s\S]*plantillas de vulnerabilidades conocidas/);
  });

  it("a critical gap stops the agent from asking to close the phase", async () => {
    // Recon's central work with no source at all: simulate a capability with neither tool nor fallback.
    const { openGap } = await import("../src/tools/capabilities.js");
    openGap(eng, { capability: "port_scan", severity: "blocked", tools: ["nmap"], phase: "recon", targets: ["127.0.0.1"], requestedBy: agent, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } });
    await expect(executeOperation("phase.request", { to: "mapping", summary: "listo" }, ctx(agent))).rejects.toThrow(/cannot close yet/);
    // The operator can still move on: their call.
    setPhase(eng, "mapping", human);
    expect(((await executeOperation("gap.list", { status: "accepted" }, ctx(agent))) as { gaps: unknown[] }).gaps).toHaveLength(1);
  });

  it("coverage never claims what a missing tool kept from being done: 'tested' becomes 'partial', with why", async () => {
    await run("http_probe", [`http://127.0.0.1:${webPort}`]);
    await run("vuln_templates", [`http://127.0.0.1:${webPort}`]);
    const app = eng.query({ kind: "webapp" })[0]!;
    await executeOperation("webapp.set_coverage", { webappId: app.id, category: "CONF", status: "tested" }, ctx(agent));
    await executeOperation("webapp.set_coverage", { webappId: app.id, category: "ATHN", status: "tested" }, ctx(agent));
    const cov = eng.get(app.id)!.attributes.coverage as Record<string, { status: string; note?: string }>;
    expect(cov.CONF).toMatchObject({ status: "partial", note: expect.stringMatching(/Parcial: .*plantillas de vulnerabilidades/) });
    // A category no gap touches stays as the agent said.
    expect(cov.ATHN!.status).toBe("tested");
  });

  it("a phase that starts offers the tools it usually needs ONCE, in one card", async () => {
    await executeOperation("phase.set", { phase: "analysis" }, ctx(human));
    for (let i = 0; i < 40 && !runner.listApprovals().length; i++) await new Promise((r) => setTimeout(r, 25));
    const kits = runner.listApprovals().filter((a) => a.request.kind === "install_kit");
    expect(kits).toHaveLength(1);
    expect(kits[0]!.summary).toMatch(/Análisis de vulnerabilidades.*nuclei 3\.11\.1/);
    // Writing the phase plan (what the agent does when it starts) does not offer it again.
    await executeOperation("plan.set_phase_plan", { phase: "analysis", plan: "- nuclei" }, ctx(agent));
    await executeOperation("capability.run", { capability: "vuln_templates", targets: [`http://127.0.0.1:${webPort}`] }, ctx(agent));
    await new Promise((r) => setTimeout(r, 100));
    expect(runner.listApprovals().filter((a) => a.request.kind === "install_kit" || a.request.kind === "install")).toHaveLength(1);
  });

  it("with the project's permission, a missing tool installs at once, no card, and the gap resumes", async () => {
    await executeOperation("tool.set_auto_install", { enabled: true, maxMB: 10 }, ctx(human));
    const r = await run("vuln_templates", [`http://127.0.0.1:${webPort}`]);
    expect(r).toMatchObject({ quality: "blocked" });
    expect(runner.listApprovals().filter((a) => a.request.kind === "install")).toHaveLength(0);
    const install = eng.runs(20).find((x) => x.tool === "penteos-toolbox")!;
    expect(install.actor).toMatchObject({ type: "system", id: "auto-install" });
    expect((await runner.waitForRun(install.id, 10))!.status).toBe("finished");
    expect(runner.autoInstall()).toEqual({ enabled: true, maxMB: 10 });
  });

  it("the fallbacks obey scope like any tool", async () => {
    const r = await run("http_probe", ["http://10.9.9.9"]).catch((e) => e);
    expect(JSON.stringify(r)).toMatch(/OUT_OF_SCOPE|denied/);
  });
});
