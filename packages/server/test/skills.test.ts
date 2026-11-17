import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Caller, type Engagement, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "@penteos/core";
import { afterEach, beforeEach, expect, it } from "vitest";
import { HUMAN, MAESTRO } from "../src/actors.js";
import { AgentManager } from "../src/agents/manager.js";

/**
 * Plugin guides do not fill the Maestro's memory on every step: short ones go whole into its
 * instructions, long or many ones as a list it reads from (skill_read) when the work calls for it.
 */

let dir: string;
let ws: Workspace;
let eng: Engagement;
let model: Server;
let systems: string[];
let manager: AgentManager;

const ctx = (caller: Caller): OperationContext => ({ workspace: ws, caller, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => new ToolRunner(eng, new ToolRegistry(join(dir, "tools"))) });

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-skills-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Skills", mode: "web" }, HUMAN.actor);
  systems = [];
  model = createServer((req, res) => {
    if (req.url?.endsWith("/models")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ data: [{ id: "m" }] }));
      return;
    }
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const messages = (JSON.parse(body) as { messages: Array<{ role: string; content: string }> }).messages;
      systems.push(messages.find((m) => m.role === "system")?.content ?? "");
      res.writeHead(200, { "content-type": "text/event-stream" });
      const chunk = (delta: object, finish: string | null) => `data: ${JSON.stringify({ id: "x", object: "chat.completion.chunk", created: 0, model: "m", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
      res.write(chunk({ role: "assistant", content: "Ok." }, null));
      res.write(chunk({}, "stop"));
      res.end("data: [DONE]\n\n");
    });
  });
  await new Promise<void>((r) => model.listen(0, "127.0.0.1", () => r()));
  manager = new AgentManager(ws, dir, (caller) => ctx(caller), MAESTRO, HUMAN, () => {});
  manager.configure("local", { baseUrl: `http://127.0.0.1:${(model.address() as { port: number }).port}/v1`, model: "m" });
  manager.select("local");
});
afterEach(async () => {
  await new Promise((r) => model.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

it("short guides go whole into the instructions", async () => {
  manager.usePluginSkills(() => [{ id: "acme.house/method", plugin: "Casa", title: "House method", text: "Always check /.git/ on every web app." }]);
  await manager.send(eng.info.id, "local", "hola");
  expect(systems[0]).toContain("### House method (plugin Casa)\nAlways check /.git/ on every web app.");
  expect(systems[0]).not.toContain("skill_read");
});

it("long ones go as a list with a line each, read on demand", async () => {
  const long = (first: string) => `## Heading\n${first} ${"More detail on how to do it. ".repeat(120)}`;
  manager.usePluginSkills(() => [
    { id: "acme.api/graphql", plugin: "API kit", title: "GraphQL testing", text: long("Introspect first, then test field-level authorization on every query.") },
    { id: "acme.api/jwt", plugin: "API kit", title: "JWT attacks", text: long("Try alg none, weak HMAC keys and kid injection, in that order.") },
  ]);
  await manager.send(eng.info.id, "local", "hola");
  const s = systems[0]!;
  expect(s).toContain("Read a guide with skill_read");
  expect(s).toContain("- GraphQL testing (plugin API kit) · id acme.api/graphql: Introspect first, then test field-level authorization on every query.");
  expect(s).toContain("- JWT attacks (plugin API kit) · id acme.api/jwt: Try alg none, weak HMAC keys and kid injection, in that order.");
  expect(s).not.toContain("More detail on how to do it.");
});
