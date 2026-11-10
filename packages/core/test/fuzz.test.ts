import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { combinations, countCombinations, type Engagement, executeOperation, type OperationContext, parseTemplate, processPayload, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

const human: Actor = { type: "human", id: "01JA0000000000000000000HMN" };
const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };

describe("attack generation", () => {
  it("splits the template and generates each attack type", () => {
    const { parts, defaults } = parseTemplate("GET /a?u=§x§&p=§y§ HTTP/1.1");
    expect(defaults).toEqual(["x", "y"]);
    expect(parts).toEqual(["GET /a?u=", "&p=", " HTTP/1.1"]);
    const sets = [["1", "2"], ["a", "b", "c"]];
    const all = (t: Parameters<typeof combinations>[0]) => [...combinations(t, defaults, sets)].map((c) => c.values.join(","));
    expect(all("sniper")).toEqual(["1,y", "2,y", "x,1", "x,2"]);
    expect(all("battering_ram")).toEqual(["1,1", "2,2"]);
    expect(all("pitchfork")).toEqual(["1,a", "2,b"]);
    expect(all("cluster_bomb")).toEqual(["1,a", "1,b", "1,c", "2,a", "2,b", "2,c"]);
    expect(countCombinations("cluster_bomb", 2, sets)).toBe(6);
    expect(() => parseTemplate("GET /§x HTTP/1.1")).toThrow(/unclosed/);
    expect(processPayload("a b", { prefix: "<", suffix: ">", encode: "url" })).toBe("%3Ca%20b%3E");
  });
});

let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let origin: string;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-fuzz-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Fuzz", mode: "web", maxRisk: "exploitation" }, human);
  // id=7 exists (different size), id=13 is slow, "admin" leaks a token.
  server = createServer((req, res) => {
    const u = new URL(req.url!, "http://x");
    const id = u.searchParams.get("id");
    const user = u.searchParams.get("user");
    const send = () => {
      if (user === "admin") return res.end("bienvenido admin token=abc123 ".repeat(5));
      if (id === "7") return res.end("item 7: un producto con una descripción bastante más larga que las demás".repeat(3));
      res.statusCode = id === "0" ? 500 : 404;
      res.end("no existe");
    };
    if (id === "13") setTimeout(send, 400);
    else send();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" } }, human);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
});

afterEach(async () => {
  for (const r of eng.runs(20)) if (r.status === "running") runner.cancel(r.id);
  await new Promise((r) => setTimeout(r, 50));
  server.close();
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

async function finished(runId: string) {
  for (let i = 0; i < 200; i++) {
    const r = eng.getRun(runId)!;
    if (r.status !== "running") return r;
    await new Promise((res) => setTimeout(res, 25));
  }
  throw new Error("fuzzing did not finish");
}

describe("fuzzing a real server", () => {
  it("finds the different responses against the baseline", async () => {
    const r = (await executeOperation("fuzz.start", { origin, template: "GET /item?id=§1§ HTTP/1.1\n\n", sets: [{ type: "numbers", from: 0, to: 15 }], grep: ["/token=\\w+/"] }, ctx(human))) as { runId: string };
    const run = await finished(r.runId);
    expect(run.status).toBe("finished");
    const res = (await executeOperation("fuzz.results", { runId: r.runId, onlyAnomalies: true }, ctx(agent))) as { done: number; anomalies: number; rows: Array<{ payloads: string[]; anomalies: string[]; status?: number }> };
    expect(res.done).toBe(17); // baseline + 16
    const by = Object.fromEntries(res.rows.map((x) => [x.payloads[0], x.anomalies]));
    expect(by["0"]).toEqual(expect.arrayContaining(["status 404→500"]));
    expect(by["7"]).toEqual(expect.arrayContaining(["status 404→200", expect.stringMatching(/^size \+/)]));
    expect(Object.keys(by).sort()).toEqual(["0", "13", "7"].sort().filter((k) => k !== "13" || by["13"]));
    // Every exchange is kept as evidence.
    const first = (await executeOperation("fuzz.results", { runId: r.runId, limit: 1 }, ctx(human))) as { rows: Array<{ rawId?: string }> };
    expect(eng.readRaw(first.rows[0]!.rawId!).toString()).toContain("GET /item?id=1 HTTP/1.1");
  });

  it("grep and extract, a wordlist file and a cluster bomb", async () => {
    const words = join(dir, "users.txt");
    writeFileSync(words, "# comentario\nguest\nadmin\nroot\n");
    const r = (await executeOperation(
      "fuzz.start",
      { origin, template: "GET /login?user=§u§&lang=§es§ HTTP/1.1\n\n", attack: "cluster_bomb", sets: [{ type: "file", path: words }, { type: "list", items: ["es", "en"] }], grep: ["token="], extract: "token=(\\w+)" },
      ctx(human),
    )) as { runId: string };
    await finished(r.runId);
    const res = (await executeOperation("fuzz.results", { runId: r.runId, onlyAnomalies: true }, ctx(human))) as { done: number; rows: Array<{ payloads: string[]; matches: string[]; extracted?: string }> };
    expect(res.done).toBe(7);
    expect(res.rows.map((x) => x.payloads[0])).toEqual(["admin", "admin"]);
    expect(res.rows[0]).toMatchObject({ matches: ["token="], extracted: "abc123" });
  });

  it("follows the rules: scope, size limit, agents need approval and the right phase", async () => {
    await expect(executeOperation("fuzz.start", { origin: "http://example.com", template: "GET /§a§ HTTP/1.1\n\n", sets: [{ type: "builtin", name: "rutas" }] }, ctx(human))).rejects.toMatchObject({ code: "OUT_OF_SCOPE" });
    await expect(executeOperation("fuzz.start", { origin, template: "GET /§a§ HTTP/1.1\n\n", sets: [{ type: "numbers", from: 1, to: 500 }], maxRequests: 100 }, ctx(human))).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
    // The agent's ceiling is "active" and fuzzing is "intrusive": it asks.
    const a = (await executeOperation("fuzz.start", { origin, template: "GET /§a§ HTTP/1.1\n\n", sets: [{ type: "builtin", name: "rutas" }] }, ctx(agent))) as { status: string; approvalId: string };
    expect(a.status).toBe("pending_approval");
    const ok = (await executeOperation("approval.approve", { approvalId: a.approvalId }, ctx(human))) as { status: string; runId: string };
    expect(ok.status).toBe("running");
    await finished(ok.runId);
    // In the reconnaissance phase an exploitation-level attack by an agent is blocked outright.
    await expect(executeOperation("fuzz.start", { origin, template: "GET /§a§ HTTP/1.1\n\n", sets: [{ type: "builtin", name: "rutas" }], risk: "exploitation" }, ctx(agent))).rejects.toMatchObject({ code: "PHASE" });
  });

  it("can be stopped", async () => {
    const r = (await executeOperation("fuzz.start", { origin, template: "GET /item?id=§1§ HTTP/1.1\n\n", sets: [{ type: "numbers", from: 1, to: 3000 }], concurrency: 1, delayMs: 5 }, ctx(human))) as { runId: string };
    await new Promise((res) => setTimeout(res, 100));
    await executeOperation("run.cancel", { runId: r.runId }, ctx(human));
    const run = await finished(r.runId);
    expect(run.status).toBe("cancelled");
    const res = (await executeOperation("fuzz.results", { runId: r.runId, limit: 1 }, ctx(human))) as { done: number };
    expect(res.done).toBeGreaterThan(1);
    expect(res.done).toBeLessThan(3001);
  });
});

describe("anomalies against the common response", () => {
  it("a redirecting baseline does not turn every 404 into an anomaly", async () => {
    const dvwa = createServer((req, res) => {
      if (req.url === "/index.php") return res.writeHead(302, { Location: "/login.php" }).end();
      if (req.url === "/admin") return res.end("panel de administración");
      res.statusCode = 404;
      res.end("Not Found: la página no existe en este servidor");
    });
    await new Promise<void>((r) => dvwa.listen(0, "127.0.0.1", () => r()));
    const o = `http://127.0.0.1:${(dvwa.address() as { port: number }).port}`;
    const r = (await executeOperation("fuzz.start", { origin: o, template: "GET /§index.php§ HTTP/1.1\n\n", sets: [{ type: "builtin", name: "rutas" }] }, ctx(human))) as { runId: string };
    await finished(r.runId);
    const res = (await executeOperation("fuzz.results", { runId: r.runId, onlyAnomalies: true }, ctx(agent))) as { anomalies: number; rows: Array<{ payloads: string[]; anomalies: string[] }> };
    dvwa.close();
    expect(res.rows.map((x) => x.payloads[0])).toEqual(["admin"]);
    expect(res.rows[0]!.anomalies).toContain("status 404→200");
  });
});
