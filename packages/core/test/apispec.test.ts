import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Caller, type Engagement, executeOperation, type OperationContext, parseApiSpec, samplePath, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/** An API that publishes its contract: every route reaches the graph, and the sweep tests them all. */

const MAESTRO: Caller = { actor: { type: "agent", id: "01JA000000000000000000MSTR" }, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } };

const SPEC = {
  openapi: "3.0.0",
  info: { title: "Northwind API", version: "3.1" },
  servers: [{ url: "/api" }],
  security: [{ bearer: [] }],
  paths: {
    "/auth/login": { post: { security: [], requestBody: {}, summary: "Login" } },
    "/tenants/public/{slug}": { get: { security: [], parameters: [{ name: "slug", in: "path" }] } },
    "/documentos/{id}": { get: { parameters: [{ name: "id", in: "path" }] }, delete: {} },
    "/documentos/{id}/export": { get: { parameters: [{ name: "id", in: "path" }] } },
    "/users": { get: { parameters: [{ name: "page", in: "query" }] } },
  },
};

describe("reading a contract", () => {
  it("lists routes with the base path, methods, parameters and declared authentication", () => {
    const p = parseApiSpec(SPEC);
    expect(p.title).toBe("Northwind API");
    expect(p.basePath).toBe("/api");
    const login = p.endpoints.find((e) => e.path === "/api/auth/login")!;
    expect(login).toMatchObject({ method: "POST", requiresAuth: false });
    expect(p.endpoints.find((e) => e.path === "/api/users")).toMatchObject({ method: "GET", requiresAuth: true, params: [{ name: "page", location: "query" }] });
    expect(p.endpoints.filter((e) => e.path === "/api/documentos/{id}").map((e) => e.method).sort()).toEqual(["DELETE", "GET"]);
  });

  it("reads Swagger 2 too, and refuses what is not a contract", () => {
    const p = parseApiSpec({ swagger: "2.0", basePath: "/v1", paths: { "/items/{id}": { get: {} } } });
    expect(p.endpoints).toEqual([{ method: "GET", path: "/v1/items/{id}", params: [] }]);
    expect(() => parseApiSpec({ hello: "world" })).toThrow(/not an OpenAPI/);
  });

  it("turns templates into requestable paths", () => {
    expect(samplePath("/api/documentos/{id}/export")).toBe("/api/documentos/1/export");
    expect(samplePath("/admin/users/:userId")).toBe("/admin/users/1");
  });
});

describe("from the contract to the sweep", () => {
  let dir: string;
  let ws: Workspace;
  let eng: Engagement;
  let runner: ToolRunner;
  let server: Server;
  let origin: string;
  const ctx = (): OperationContext => ({ workspace: ws, caller: MAESTRO, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner });

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), "penteos-apispec-"));
    ws = new Workspace(join(dir, "data"));
    eng = ws.create({ clientName: "Lab", name: "API", mode: "web" }, MAESTRO.actor);
    server = createServer((req, res) => {
      if (req.url === "/api/docs-json") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(SPEC));
        return;
      }
      // The export forgot its guard; everything else secured answers 401.
      if (req.url === "/api/documentos/1/export" || req.url?.startsWith("/api/tenants/public/")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end('{"ok":true}');
        return;
      }
      res.writeHead(401);
      res.end("{}");
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as { port: number }).port;
    origin = `http://127.0.0.1:${port}`;
    eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, MAESTRO.actor);
    runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
  });

  afterEach(async () => {
    await new Promise((r) => server.close(r));
    ws.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("puts every route in the graph, records the open contract, and the sweep finds the forgotten guard", async () => {
    const read = (await executeOperation("web.read_api_spec", { url: `${origin}/api/docs-json` }, ctx())) as { status: string; routes: number };
    expect(read).toMatchObject({ status: "done", routes: 5 });
    expect(eng.query({ kind: "observation", limit: 20 }).some((o) => o.attributes.sourceRule === "apispec:exposed")).toBe(true);

    const probe = (await executeOperation("web.probe_endpoints", { origin }, ctx())) as { probed: number; withoutAuth: string[] };
    expect(probe.probed).toBe(5);
    // The public tenant lookup is declared public: not a gap. The export is declared secured: a gap.
    expect(probe.withoutAuth).toEqual(["/api/documentos/{id}/export"]);
    const obs = eng.query({ kind: "observation", limit: 20 }).find((o) => o.attributes.sourceRule === "apiprobe:no-auth")!;
    expect(obs.attributes.severityHint).toBe("high");
    expect(String(obs.attributes.detail)).toMatch(/contract says it requires authentication/);
  });
});
