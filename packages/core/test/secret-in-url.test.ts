import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, expect, it } from "vitest";
import { type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/** A run showed it: a saved secret in the path or the query left literally, as "{{secret:…}}". */

const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let origin: string;
const seen: string[] = [];

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-secret-url-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Secret URL", mode: "web" }, agent);
  seen.length = 0;
  server = createServer((req, res) => {
    seen.push(req.url ?? "");
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  origin = `http://127.0.0.1:${port}`;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, agent);
  eng.saveSecret({ name: "form_token", kind: "token", value: "tok-123abc" }, agent);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
});

afterEach(async () => {
  await new Promise((r) => server.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const ctx = (): OperationContext => ({
  workspace: ws,
  caller: { actor: agent, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } },
  defaultEngagementId: eng.info.id,
  engagement: () => eng,
  runner: () => runner,
});

it("resolves secrets in the path and the query before sending", async () => {
  await executeOperation("http.send", { origin, raw: "GET /forms/{{secret:form_token}}/view HTTP/1.1" }, ctx());
  await executeOperation("http.send", { origin, raw: "GET /forms/view?token={{secret:form_token}} HTTP/1.1" }, ctx());
  expect(seen).toEqual(["/forms/tok-123abc/view", "/forms/view?token=tok-123abc"]);
  // What the run records keeps the reference, never the value.
  const commands = eng.runs(10).map((r) => r.command ?? "");
  expect(commands.some((c) => c.includes("tok-123abc"))).toBe(false);
});

it("never lets a secret change the destination host", async () => {
  eng.saveSecret({ name: "evil_host", kind: "token", value: "http://203.0.113.9" }, agent);
  const r = (await executeOperation("http.send", { origin, raw: "GET {{secret:evil_host}}/x HTTP/1.1" }, ctx()).catch((e: Error) => ({ error: e.message }))) as { error?: string; status?: string };
  expect(seen).toEqual([]);
  expect(JSON.stringify(r)).toMatch(/host|scope|denied|failed/i);
});
