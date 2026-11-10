import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Caller, type Engagement, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "@penteos/core";
import { afterEach, beforeEach, expect, it } from "vitest";
import { HUMAN, MAESTRO } from "../src/actors.js";
import { AgentManager } from "../src/agents/manager.js";

/** A provider's API key never sits in clear on disk: sealed with the workspace key, open only in memory. */

let dir: string;
let ws: Workspace;
let eng: Engagement;

const ctx = (caller: Caller): OperationContext => ({
  workspace: ws,
  caller,
  defaultEngagementId: eng.info.id,
  engagement: () => eng,
  runner: () => new ToolRunner(eng, new ToolRegistry(join(dir, "tools"))),
});
const manager = () => new AgentManager(ws, dir, (caller) => ctx(caller), MAESTRO, HUMAN, () => undefined);
const onDisk = () => readFileSync(join(dir, "config", "agents.json"), "utf8");
const KEY = "sk-test-0123456789abcdef";

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-keys-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Keys", mode: "web" }, HUMAN.actor);
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

it("seals the key on disk and reads it back after a restart", async () => {
  manager().configure("claude-api", { apiKey: KEY });
  expect(onDisk()).not.toContain(KEY);
  expect(JSON.parse(onDisk()).providers["claude-api"].apiKey).toMatch(/^v1:/);
  const status = (await manager().providers(eng.info.id)).providers.find((p) => p.id === "claude-api");
  expect(status?.settings).toMatchObject({ hasApiKey: true });
});

it("seals a key an older version saved in clear, on the next start", () => {
  mkdirSync(join(dir, "config"), { recursive: true });
  writeFileSync(join(dir, "config", "agents.json"), JSON.stringify({ providers: { "claude-api": { apiKey: KEY } } }));
  manager();
  expect(onDisk()).not.toContain(KEY);
});
