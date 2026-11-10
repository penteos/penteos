import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Caller, type Engagement, type OperationContext, type PluginProviderInfo, ToolRegistry, ToolRunner, Workspace } from "@penteos/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { HUMAN, MAESTRO } from "../src/actors.js";
import { AgentManager } from "../src/agents/manager.js";

/**
 * A plugin's AI provider: listed with the others, always remote (so what
 * the model reads is masked), pointed only where the plugin says, and gone when the plugin is.
 */

let dir: string;
let ws: Workspace;
let eng: Engagement;
let model: Server;
let port: number;
let requests: Array<{ auth?: string; body: string }>;
let manager: AgentManager;
let offered: PluginProviderInfo[];

const ctx = (caller: Caller): OperationContext => ({
  workspace: ws,
  caller,
  defaultEngagementId: eng.info.id,
  engagement: () => eng,
  runner: () => new ToolRunner(eng, new ToolRegistry(join(dir, "tools"))),
});

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-plugin-llm-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "LLM", mode: "web" }, HUMAN.actor);
  requests = [];
  model = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += String(d)));
    req.on("end", () => {
      requests.push({ ...(req.headers.authorization ? { auth: req.headers.authorization } : {}), body });
      res.writeHead(200, { "content-type": "text/event-stream" });
      const chunk = (delta: object, finish: string | null) => `data: ${JSON.stringify({ id: "x", object: "chat.completion.chunk", created: 0, model: "m", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
      res.write(chunk({ role: "assistant", content: "Listo." }, null));
      res.write(chunk({}, "stop"));
      res.end("data: [DONE]\n\n");
    });
  });
  await new Promise<void>((r) => model.listen(0, "127.0.0.1", () => r()));
  port = (model.address() as { port: number }).port;
  manager = new AgentManager(ws, dir, (caller) => ctx(caller), MAESTRO, HUMAN, () => undefined);
  offered = [{ key: "plugin:lab.llm:groq", pluginId: "lab.llm", id: "groq", label: "Groq (lab)", baseUrl: `http://127.0.0.1:${port}/v1`, models: ["m-large", "m-small"], apiKey: "PLUGIN-KEY-123" }];
  manager.usePluginProviders(() => offered);
});

afterEach(async () => {
  await new Promise((r) => model.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("a plugin's AI provider", () => {
  it("is listed as a remote API, talks to its own endpoint with its own key, and the model reads masked data", async () => {
    // Only where its plugin is enabled: it takes the project's data to a third party.
    expect((await manager.providers(eng.info.id, true)).providers.find((x) => x.id === "plugin:lab.llm:groq")).toMatchObject({ available: false });
    eng.setInfo({ ...eng.info, plugins: ["lab.llm"] }, HUMAN.actor);
    const { providers } = await manager.providers(eng.info.id, true);
    const p = providers.find((x) => x.id === "plugin:lab.llm:groq");
    expect(p).toMatchObject({ kind: "api", available: true, label: "Groq (lab)" });

    // Saved settings cannot point it elsewhere.
    manager.configure("plugin:lab.llm:groq", { baseUrl: "http://127.0.0.1:1/v1", apiKey: "other" } as never);
    await manager.send(eng.info.id, "plugin:lab.llm:groq", "Revisá a juan.perez@cliente-real.test y su tarjeta 4111 1111 1111 1111");
    expect(requests).toHaveLength(1);
    expect(requests[0]!.auth).toBe("Bearer PLUGIN-KEY-123");
    expect(requests[0]!.body).toContain('"model":"m-large"');
    // Remote, so masked: the real values never reach the plugin's endpoint.
    expect(requests[0]!.body).not.toContain("juan.perez@cliente-real.test");
    expect(requests[0]!.body).not.toContain("4111 1111 1111 1111");
  }, 30000);

  it("is gone with its plugin, and the project policy applies to it like to any API", async () => {
    offered = [];
    manager.invalidateProviders();
    expect((await manager.providers(eng.info.id, true)).providers.some((x) => x.id.startsWith("plugin:"))).toBe(false);

    offered = [{ key: "plugin:lab.llm:groq", pluginId: "lab.llm", id: "groq", label: "Groq (lab)", baseUrl: `http://127.0.0.1:${port}/v1`, models: ["m"], apiKey: "k" }];
    manager.invalidateProviders();
    eng.setInfo({ ...eng.info, plugins: ["lab.llm"], dataPolicy: "local_only" }, HUMAN.actor);
    const p = (await manager.providers(eng.info.id, true)).providers.find((x) => x.id === "plugin:lab.llm:groq");
    expect(p?.available).toBe(false);
  });
});
