import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Caller, type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";
import { deepSignals, jsReferences, recoverSources, safeSourcePath, sourceMapUrl } from "../src/webjs-deep.js";

/**
 * All of a web app's JavaScript, not only what its first page loads: the chunks it names, the
 * source maps it serves (the original code), and what that code reveals - configuration, message
 * listeners without an origin check, redirect parameters, client-computed fields, server actions.
 */

describe("reading the code", () => {
  it("finds the scripts a script names: chunks, imports, the Next.js build manifest", () => {
    const code = `self.__next_f.push([1,"static/chunks/app/admin/page-1a2b.js"]);import("./lazy-9f.js");"buildId":"Xy12abCD34"`;
    expect(jsReferences(code, "https://app.test/_next/static/chunks/main.js").sort()).toEqual(
      ["https://app.test/_next/static/Xy12abCD34/_buildManifest.js", "https://app.test/_next/static/Xy12abCD34/_ssgManifest.js", "https://app.test/_next/static/chunks/app/admin/page-1a2b.js", "https://app.test/_next/static/chunks/lazy-9f.js"].sort(),
    );
    expect(jsReferences(`require("react.js")`, "https://app.test/x.js")).toEqual([]);
  });

  it("finds the source map by comment or header, and recovers the original files safely", () => {
    expect(sourceMapUrl("x\n//# sourceMappingURL=main.js.map", [], "https://app.test/s/main.js")).toBe("https://app.test/s/main.js.map");
    expect(sourceMapUrl("x", [["SourceMap", "/maps/m.map"]], "https://app.test/s/main.js")).toBe("https://app.test/maps/m.map");
    expect(sourceMapUrl("//# sourceMappingURL=data:application/json;base64,e30=", [], "https://app.test/a.js")).toBeUndefined();
    const sources = recoverSources(JSON.stringify({ version: 3, sources: ["webpack://app/./src/../../etc/passwd", "webpack://app/./src/api.ts"], sourcesContent: ["x", "export const api = 1"] }))!;
    expect(sources.map((s) => s.path)).toEqual(["app/src/etc/passwd", "app/src/api.ts"]);
    expect(safeSourcePath("../../../../root/.ssh/id_rsa")).toBe("root/.ssh/id_rsa");
    expect(recoverSources("not json")).toBeUndefined();
  });

  it("reads what the code reveals beyond endpoints", () => {
    const code = [
      `Sentry.init({dsn:"https://0123456789abcdef0123456789abcdef@o123.ingest.sentry.io/456"})`,
      `const u = process.env.NEXT_PUBLIC_API_URL; fetch("http://10.20.0.5:8080/health")`,
      `window.addEventListener("message", (e) => { document.body.innerHTML = e.data })`,
      `router.push(params.redirectUrl); const body = { email, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, ip: myIp }`,
      `(0,a.createServerReference)("7f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6e5",a.callServer,void 0,a.findSourceMapURL,"deleteUser")`,
    ].join("\n");
    const s = deepSignals(code, "sources/app/page.tsx");
    expect(s.config.map((c) => c.kind)).toContain("Sentry DSN");
    expect(s.configNames).toContain("NEXT_PUBLIC_API_URL");
    expect(s.internalAddresses).toContain("10.20.0.5:8080");
    expect(s.messageListeners).toEqual([{ file: "sources/app/page.tsx", checksOrigin: false }]);
    expect(s.sinks.map((x) => x.kind)).toContain("innerHTML");
    expect(s.redirectParams).toContain("redirecturl");
    expect(s.clientFields).toEqual(expect.arrayContaining(["timezone", "ip"]));
    expect(s.serverActions).toEqual([{ id: "7f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6e5", name: "deleteUser", file: "sources/app/page.tsx" }]);
    // A listener that checks the sender is not flagged; libraries' code is not the app's.
    expect(deepSignals(`addEventListener("message", e => { if (e.origin !== ORIGIN) return; })`, "a.js").messageListeners[0]!.checksOrigin).toBe(true);
    expect(deepSignals(`addEventListener("message", e => 1); el.innerHTML = x`, "sources/node_modules/lib/x.js").sinks).toEqual([]);
  });
});

const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let origin: string;
const hits: string[] = [];
const ctx = (): OperationContext => ({ workspace: ws, caller: HUMAN, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner }) as unknown as OperationContext;

const ACTION_OPEN = "40aa".padEnd(42, "1");
const ACTION_GUARDED = "40bb".padEnd(42, "2");
const ACTION_BROKEN = "40cc".padEnd(42, "3");
const FILES: Record<string, { type: string; body: string }> = {
  "/": { type: "text/html", body: `<html><script src="/_next/static/chunks/main-1.js"></script><script>self.__next_f.push([1,"static/chunks/app/login/page-2.js"])</script></html>` },
  "/_next/static/chunks/main-1.js": { type: "application/javascript", body: `import("./lazy-3.js");\n//# sourceMappingURL=main-1.js.map` },
  "/_next/static/chunks/main-1.js.map": { type: "application/json", body: JSON.stringify({ version: 3, sources: ["webpack://app/./src/api/admin.ts"], sourcesContent: [`export const adminApi = "/api/internal/users";\nwindow.addEventListener("message", (e) => run(e.data));`] }) },
  "/_next/static/chunks/app/login/page-2.js": { type: "application/javascript", body: `(0,a.createServerReference)("${ACTION_OPEN}",a.callServer,void 0,a.findSourceMapURL,"checkEmail");(0,a.createServerReference)("${ACTION_GUARDED}",a.callServer,void 0,a.findSourceMapURL,"listUsers");(0,a.createServerReference)("${ACTION_BROKEN}",a.callServer,void 0,a.findSourceMapURL,"loadTenant");location.href = q.returnTo` },
  "/_next/static/chunks/lazy-3.js": { type: "application/javascript", body: `fetch("/api/v2/tenants")` },
};

beforeEach(async () => {
  hits.length = 0;
  dir = mkdtempSync(join(tmpdir(), "penteos-deepjs-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "JS", mode: "web" }, HUMAN.actor);
  server = createServer((req, res) => {
    hits.push(`${req.method} ${req.url}`);
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      const action = req.headers["next-action"];
      if (req.method === "POST" && action) {
        if (action === ACTION_OPEN) return void res.writeHead(200, { "content-type": "text/x-component" }).end(`0:{"a":"$@1"}\n1:{"exists":true}`);
        if (action === ACTION_GUARDED) return void res.writeHead(401).end("Unauthorized");
        if (action === ACTION_BROKEN) return void res.writeHead(500).end("Error: Cannot read properties of undefined");
        return void res.writeHead(404).end("Server action not found");
      }
      const f = FILES[req.url ?? ""];
      if (!f) return void res.writeHead(404).end("no");
      res.writeHead(200, { "content-type": f.type }).end(f.body);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  origin = `http://127.0.0.1:${port}`;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, HUMAN.actor);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
});
afterEach(async () => {
  await new Promise((r) => server.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("harvesting a whole app", () => {
  it("follows every chunk, recovers the source, keeps it all in the project, and opens the leads", async () => {
    const r = (await executeOperation("web.harvest_scripts", { url: `${origin}/` }, ctx())) as { status: string; runId: string };
    const run = eng.getRun(r.runId ?? (r as unknown as { run: { id: string } }).run?.id)!;
    const summary = run.summary as { scriptsRead: number; sourceFilesRecovered: number; serverActions: number; savedIn: string };
    // main-1 (from the HTML), page-2 (from the RSC payload), lazy-3 (imported by main-1): none missed.
    expect(hits).toEqual(expect.arrayContaining(["GET /_next/static/chunks/main-1.js", "GET /_next/static/chunks/app/login/page-2.js", "GET /_next/static/chunks/lazy-3.js", "GET /_next/static/chunks/main-1.js.map"]));
    expect(summary.sourceFilesRecovered).toBe(1);
    expect(summary.serverActions).toBe(3);
    expect(readFileSync(join(summary.savedIn, "sources/app/src/api/admin.ts"), "utf8")).toContain("/api/internal/users");
    expect(existsSync(join(summary.savedIn, "bundles/_next/static/chunks/lazy-3.js"))).toBe(true);
    expect(existsSync(join(summary.savedIn, "index.json"))).toBe(true);
    const titles = eng.query({ kind: "observation", limit: 100 }).map((o) => `${o.attributes.sourceRule} · ${o.attributes.title}`);
    expect(titles.join("\n")).toMatch(/webjs:sources-exposed · Source code exposed through source maps: 1 original files/);
    expect(titles.join("\n")).toMatch(/lead:postmessage · Message listener without an origin check in sources\/app\/src\/api\/admin\.ts/);
    expect(titles.join("\n")).toMatch(/lead:redirect · Redirect parameters in the code: returnto/);
    expect(titles.join("\n")).toMatch(/lead:server-actions · 3 Next\.js server action\(s\) in the bundles: checkEmail, listUsers, loadTenant/);
    // Endpoints from the recovered source reach the graph too.
    expect(eng.query({ kind: "endpoint", limit: 100 }).map((e) => String(e.attributes.pathTemplate ?? e.naturalKey))).toEqual(expect.arrayContaining([expect.stringContaining("/api/internal/users")]));
  });

  it("calls each server action without a session and says which ran", async () => {
    await executeOperation("web.harvest_scripts", { url: `${origin}/` }, ctx());
    const r = (await executeOperation("web.probe_server_actions", { origin, page: "/login" }, ctx())) as { ran: string[]; protected: number; failed: string[]; missing: number };
    expect(r).toMatchObject({ ran: ["checkEmail"], protected: 1, failed: ["loadTenant"], missing: 0 });
    const titles = eng.query({ kind: "observation", limit: 100 }).map((o) => String(o.attributes.title));
    expect(titles).toEqual(expect.arrayContaining([expect.stringMatching(/Server action checkEmail runs without a session \(200\)/), expect.stringMatching(/Server error on server action loadTenant \(500\)/)]));
    expect(hits.filter((h) => h.startsWith("POST /login"))).toHaveLength(3);
  });
});
