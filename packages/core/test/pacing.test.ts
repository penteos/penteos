import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { type Caller, executeOperation, type OperationContext, Workspace } from "../src/index.js";
import { sendHttp } from "../src/http.js";
import { acquire, hostOfTarget, isLocalHost, observe, paceArguments, paceStats, resetPacing, retryAfterMs, withPace } from "../src/pacing.js";

/**
 * A client's production site is not a lab: what Penteos sends waits for the host's turn at the
 * project's pace, a 429 or 503 pauses the host (and a plain read is tried again once), and the
 * external tools get matching rate options.
 */

beforeEach(() => resetPacing());

describe("the host's turn", () => {
  it("quiet: a burst of 4, then 2 per second", async () => {
    const t0 = Date.now();
    for (let i = 0; i < 6; i++) (await acquire("app.client.test", "quiet"))();
    // 4 at once, then two more at 2/s: about a second.
    expect(Date.now() - t0).toBeGreaterThanOrEqual(850);
    expect(paceStats((h) => h === "app.client.test")[0]!.sent).toBe(6);
  });

  it("one request in flight at a time when quiet", async () => {
    const first = await acquire("one.client.test", "quiet");
    let second = false;
    const pending = acquire("one.client.test", "quiet").then((r) => ((second = true), r));
    await new Promise((r) => setTimeout(r, 300));
    expect(second).toBe(false);
    first();
    (await pending)();
    expect(second).toBe(true);
  });

  it("off and this machine go at once", async () => {
    const t0 = Date.now();
    for (let i = 0; i < 50; i++) (await acquire("lab.test", "off"))();
    for (let i = 0; i < 50; i++) (await acquire("127.0.0.1", "quiet"))();
    for (let i = 0; i < 50; i++) (await acquire("localhost", "quiet"))();
    expect(Date.now() - t0).toBeLessThan(300);
    expect(isLocalHost("::1")).toBe(true);
    expect(isLocalHost("10.0.0.5")).toBe(false);
  });

  it("a 429 pauses the host for its Retry-After, and the backoff doubles without one", async () => {
    (await acquire("busy.client.test", "normal"))();
    expect(observe("busy.client.test", 429, "1", "normal")).toBe(true);
    const t0 = Date.now();
    (await acquire("busy.client.test", "normal"))();
    expect(Date.now() - t0).toBeGreaterThanOrEqual(900);
    expect(paceStats((h) => h === "busy.client.test")[0]!.throttled).toBe(1);
    expect(observe("busy.client.test", 200, undefined, "normal")).toBe(false);
    expect(retryAfterMs("2")).toBe(2000);
    expect(retryAfterMs(new Date(Date.now() + 5000).toUTCString())).toBeGreaterThan(3000);
  });
});

describe("what Penteos sends", () => {
  let server: Server;
  let origin: string;
  let hits: string[] = [];
  let answers: number[] = [];
  beforeAll(async () => {
    process.env.PENTEOS_PACE_LOCAL = "1";
    server = createServer((req, res) => {
      hits.push(`${req.method} ${req.url}`);
      const status = answers.shift() ?? 200;
      res.writeHead(status, status === 429 ? { "retry-after": "1" } : {}).end(String(status));
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });
  afterAll(async () => {
    delete process.env.PENTEOS_PACE_LOCAL;
    await new Promise((r) => server.close(r));
  });
  afterEach(() => {
    hits = [];
    answers = [];
  });

  it("a GET answered 429 waits the pause and goes again once", async () => {
    answers = [429, 200];
    const t0 = Date.now();
    const u = new URL(`${origin}/a`);
    const r = await withPace("normal", () => sendHttp(u, { method: "GET", path: "/a", headers: [["Host", u.host]], body: "" }));
    expect(r.status).toBe(200);
    expect(hits).toEqual(["GET /a", "GET /a"]);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(900);
  });

  it("a POST is never sent twice: the 429 comes back as it is", async () => {
    answers = [429];
    const u = new URL(`${origin}/transfer`);
    const r = await withPace("normal", () => sendHttp(u, { method: "POST", path: "/transfer", headers: [["Host", u.host]], body: "{}" }));
    expect(r.status).toBe(429);
    expect(hits).toEqual(["POST /transfer"]);
  });
});

describe("the external tools", () => {
  it("get rate options from the pace, unless the command sets its own", () => {
    expect(paceArguments("/home/x/.penteos/bin/nuclei", ["-u", "https://a.test"], "normal")).toEqual({ argv: ["-u", "https://a.test", "-rl", "5", "-c", "4"], added: "-rl 5 -c 4" });
    expect(paceArguments("nuclei", ["-u", "https://a.test", "-rl", "50"], "quiet").argv).toEqual(["-u", "https://a.test", "-rl", "50", "-c", "2"]);
    expect(paceArguments("ffuf", ["-u", "https://a.test/FUZZ", "-w", "w.txt"], "quiet").added).toBe("-rate 2 -t 1");
    expect(paceArguments("sqlmap", ["-u", "https://a.test/?id=1"], "normal").added).toBe("--delay=0.20 --threads=1");
    expect(paceArguments("nmap", ["-sV", "10.0.0.5"], "quiet").added).toBe("-T2");
    expect(paceArguments("nmap", ["-T4", "10.0.0.5"], "quiet").added).toBeUndefined();
    expect(paceArguments("curl", ["https://a.test"], "quiet").added).toBeUndefined();
    expect(paceArguments("nuclei", ["-u", "x"], "off").added).toBeUndefined();
  });

  it("know which host a target names", () => {
    expect(hostOfTarget("https://app.client.test:8443/login")).toBe("app.client.test");
    expect(hostOfTarget("app.client.test:8080")).toBe("app.client.test");
    expect(hostOfTarget("10.0.0.0/24")).toBe("10.0.0.0");
    expect(hostOfTarget("[::1]:80")).toBe("::1");
    expect(hostOfTarget("127.0.0.1")).toBe("127.0.0.1");
  });
});

describe("the project's pace", () => {
  const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };
  let dir: string;
  let ws: Workspace;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "penteos-pacing-"));
    ws = new Workspace(join(dir, "data"));
  });
  afterEach(() => {
    ws.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("is normal by default, and the operator sets it", async () => {
    const eng = ws.create({ clientName: "Client", name: "Prod", mode: "web" }, HUMAN.actor);
    const ctx = { workspace: ws, caller: HUMAN, defaultEngagementId: eng.info.id, engagement: () => eng } as unknown as OperationContext;
    expect(((await executeOperation("pacing.get", {}, ctx)) as { pace: string }).pace).toBe("normal");
    await executeOperation("pacing.set", { pace: "quiet" }, ctx);
    const got = (await executeOperation("pacing.get", {}, ctx)) as { pace: string; limits: { rps: number } };
    expect(got.pace).toBe("quiet");
    expect(got.limits.rps).toBe(2);
    const agent: Caller = { actor: { type: "agent", id: "01JA0000000000000000000AGT" }, policy: { type: "agent", autonomy: "autonomous", maxRisk: "passive" } };
    await expect(executeOperation("pacing.set", { pace: "off" }, { ...ctx, caller: agent } as OperationContext)).rejects.toThrow(/cannot be called by agents/);
  });
});
