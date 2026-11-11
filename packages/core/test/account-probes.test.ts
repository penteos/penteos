import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { BUILTIN, type Caller, type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/**
 * With test accounts, where a wallet's critical issues live: one account reading another's
 * resource, a transfer accepted several times at once, a session that survives logging out.
 */
const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let origin: string;
let transfers = 0;
const ctx = (): OperationContext => ({ workspace: ws, caller: HUMAN, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner }) as unknown as OperationContext;

beforeEach(async () => {
  transfers = 0;
  dir = mkdtempSync(join(tmpdir(), "penteos-accounts-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Wallet", mode: "web" }, HUMAN.actor);
  server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      const session = /sid=(\w+)/.exec(req.headers.cookie ?? "")?.[1];
      if (req.url === "/api/accounts/1001") {
        // The bug: any session reads account 1001 (it belongs to A).
        if (!session) return void res.writeHead(401).end("{}");
        return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ id: 1001, owner: "ana", cvu: "0000003100012345678901", balance: 5230.5 }));
      }
      if (req.url === "/api/transfer" && req.method === "POST") {
        transfers++;
        return void setTimeout(() => res.writeHead(200).end(`{"ok":true,"n":${transfers}}`), 30);
      }
      if (req.url === "/api/user") return void (session ? res.writeHead(200).end(`{"user":"${session}","email":"a@lab.test"}`) : res.writeHead(401).end("{}"));
      if (req.url === "/api/logout") return void res.writeHead(200).end("{}"); // the bug: nothing is invalidated
      res.writeHead(404).end();
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  origin = `http://127.0.0.1:${port}`;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, HUMAN.actor);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
  await executeOperation("secret.save", { name: "account_a", kind: "cookie", value: "sid=annaSESSION" }, ctx());
  await executeOperation("secret.save", { name: "account_b", kind: "cookie", value: "sid=bobSESSION" }, ctx());
});
afterEach(async () => {
  await new Promise((r) => server.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

it("account B reads account A's resource: IDOR, with the exchange as evidence", async () => {
  const r = (await executeOperation("web.cross_account", { origin, accountA: "Cookie: {{secret:account_a}}", accountB: "Cookie: {{secret:account_b}}", raws: ["GET /api/accounts/1001 HTTP/1.1\nCookie: {{secret:account_a}}"] }, ctx())) as { hits: string[] };
  expect(r.hits).toEqual(["high: Account B reads account A's resource: GET /api/accounts/1001 HTTP/1.1"]);
  const obs = eng.query({ kind: "observation", limit: 10 })[0]!;
  expect(String(eng.readRaw(String(obs.attributes.rawId)))).toContain("sid=bobSESSION");
});

it("a transfer accepted several times at once, and the amounts to try on it", async () => {
  const r = (await executeOperation("web.probe_race", { origin, raw: 'POST /api/transfer HTTP/1.1\nCookie: {{secret:account_a}}\nContent-Type: application/json\n\n{"to":"0000003100099999999999","amount":1}', count: 5 }, ctx())) as { hits: string[]; summary: { succeeded: number } };
  expect(r.summary.succeeded).toBe(5);
  expect(r.hits[0]).toMatch(/5 of 5 simultaneous POST \/api\/transfer/);
  expect(transfers).toBe(5);
  expect(BUILTIN.montos).toEqual(expect.arrayContaining(["-1", "0", "1e9", "NaN"]));
});

it("a session that still works after logging out", async () => {
  const r = (await executeOperation("web.probe_logout", { origin, check: "GET /api/user HTTP/1.1\nCookie: {{secret:account_a}}", logout: "POST /api/logout HTTP/1.1\nCookie: {{secret:account_a}}" }, ctx())) as { hits: string[] };
  expect(r.hits).toEqual(["medium: Session still valid after logging out"]);
});
