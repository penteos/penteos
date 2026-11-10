import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Caller, type Engagement, executeOperation, type OperationContext, setPhase, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/** Testing deeper without credentials: rate limits, and not closing the analysis with easy tests left. */

const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };
const MAESTRO: Caller = { actor: { type: "agent", id: "01JA000000000000000000MSTR" }, policy: { type: "agent", autonomy: "autonomous", maxRisk: "intrusive" } };

let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let origin: string;
let hits = 0;
/** /late-login: no defence until the test turns it on (a limit above the first probe's attempts). */
let limitOn = false;
const ctx = (caller: Caller): OperationContext => ({ workspace: ws, caller, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner });

beforeEach(async () => {
  hits = 0;
  limitOn = false;
  dir = mkdtempSync(join(tmpdir(), "penteos-depth-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ language: "es", clientName: "Lab", name: "Depth", mode: "web" }, HUMAN.actor);
  server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      // /open-login never defends itself; /guarded-login answers 429 from the fifth attempt.
      if ((req.url === "/guarded-login" && ++hits >= 5) || (req.url === "/late-login" && limitOn)) {
        res.writeHead(429);
        res.end("slow down");
        return;
      }
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end('{"error":"invalid credentials"}');
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

const login = (path: string) => `POST ${path} HTTP/1.1\nContent-Type: application/json\n\n{"user":"penteos-test","password":"wrong"}`;

describe("rate limiting", () => {
  it("records an observation when every attempt is accepted, after at least 15 of them", async () => {
    // Asked for 8: limits commonly start between 10 and 20, so 8 could only say "none seen yet".
    const r = (await executeOperation("web.probe_rate_limit", { origin, raw: login("/open-login"), attempts: 8 }, ctx(MAESTRO))) as { attempts: number; defence: string | null };
    expect(r).toMatchObject({ attempts: 15, defence: null });
    expect(eng.query({ kind: "observation", limit: 20 }).some((o) => o.attributes.sourceRule === "ratelimit:none")).toBe(true);
  });

  it("a 429 seen later on the same endpoint settles an earlier 'no rate limiting'", async () => {
    await executeOperation("web.probe_rate_limit", { origin, raw: login("/late-login") }, ctx(MAESTRO));
    const before = eng.query({ kind: "observation", limit: 20 }).find((o) => o.attributes.sourceRule === "ratelimit:none")!;
    expect(before.attributes.triage).toBe("new");
    limitOn = true;
    await executeOperation("http.send", { origin, raw: login("/late-login") }, ctx(MAESTRO));
    const after = eng.get(before.id)!;
    expect(after.attributes.triage).toBe("false_positive");
    expect(String(after.attributes.triageReason)).toContain("429");
  });

  it("stops at the first defence and records nothing against the endpoint", async () => {
    const r = (await executeOperation("web.probe_rate_limit", { origin, raw: login("/guarded-login"), attempts: 20 }, ctx(MAESTRO))) as { attempts: number; defence: string | null };
    expect(r.attempts).toBe(5);
    expect(r.defence).toMatch(/429/);
    expect(eng.query({ kind: "observation", limit: 20 }).some((o) => o.attributes.sourceRule === "ratelimit:none")).toBe(false);
  });
});

it("closing the analysis lists the tests that needed no credentials and were not done", async () => {
  eng.ingest(
    {
      format: "penteos.ingest/v0",
      source: { parser: "test@0.1", tool: "test" },
      rawIds: [],
      observedAt: new Date().toISOString(),
      items: ["/api/auth/login", "/api/a", "/api/b", "/api/c", "/api/d"].map((path) => ({ op: "upsert", kind: "endpoint", key: { origin, path }, confidence: 1 })),
    } as never,
    HUMAN.actor,
  );
  setPhase(eng, "analysis", HUMAN.actor);
  const r = (await executeOperation("phase.request", { to: "exploitation", summary: "Listo" }, ctx(MAESTRO))) as { note: string };
  const warnings = runner.listApprovals()[0]!.warnings.join(" | ");
  for (const gap of ["JavaScript sin analizar", "5 endpoint(s) conocidos sin pedir nunca", "frontera de autenticación sin barrer", "login sin prueba de límite de intentos"]) expect(warnings).toContain(gap);
  expect(r.note).toMatch(/withdraw this request and do it first/);
});
