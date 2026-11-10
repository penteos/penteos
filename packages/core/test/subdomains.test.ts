import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Caller, type ChangeEvent, type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/**
 * A site whose apex redirects to www, and an operator who does not want subdomains: the agents
 * learn about the redirect, ask for exactly that host, and never get to insist on a wildcard.
 */

const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };
const MAESTRO: Caller = { actor: { type: "agent", id: "01JA000000000000000000MSTR" }, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } };

let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let events: ChangeEvent[];

const ctx = (caller: Caller): OperationContext => ({ workspace: ws, caller, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner });

const redirect = (from: string, to: string) =>
  eng.ingest(
    {
      format: "penteos.ingest/v0",
      source: { parser: "test@0.1", tool: "httpx" },
      rawIds: [],
      observedAt: new Date().toISOString(),
      items: [
        { op: "upsert", kind: "webapp", key: { origin: from }, confidence: 1 },
        { op: "observe", title: `Redirects to ${to}`, sourceRule: "httpx:redirect", affects: [{ kind: "webapp", key: { origin: from } }], severityHint: "info" },
      ],
    } as never,
    HUMAN.actor,
  );

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-subdomains-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Cliente", name: "Web", mode: "web" }, HUMAN.actor);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
  eng.addScopeRule({ effect: "include", target: { type: "domain", value: "cliente.example" } }, HUMAN.actor);
  events = [];
  eng.events.on("change", (e: ChangeEvent) => events.push(e));
});

afterEach(() => {
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("a site that redirects out of scope", () => {
  it("reports the destination host once, and not when it is in scope or the same host", () => {
    redirect("https://cliente.example", "https://www.cliente.example/");
    redirect("https://cliente.example", "https://www.cliente.example/inicio");
    redirect("https://cliente.example", "/login");
    const found = events.filter((e) => e.type === "scope.redirect_outside");
    expect(found).toEqual([{ type: "scope.redirect_outside", from: "https://cliente.example", to: "https://www.cliente.example", host: "www.cliente.example" }]);

    eng.addScopeRule({ effect: "include", target: { type: "domain", value: "sso.cliente.example" } }, HUMAN.actor);
    redirect("https://cliente.example", "https://sso.cliente.example/auth");
    expect(events.filter((e) => e.type === "scope.redirect_outside")).toHaveLength(1);
  });
});

describe("an operator who does not want subdomains", () => {
  it("a wildcard proposal says how many known names it covers; rejecting it closes the door", async () => {
    eng.ingest(
      {
        format: "penteos.ingest/v0",
        source: { parser: "test@0.1", tool: "subfinder" },
        rawIds: [],
        observedAt: new Date().toISOString(),
        items: ["a", "b", "c"].map((n) => ({ op: "upsert", kind: "domain", key: { fqdn: `${n}.cliente.example` }, confidence: 1 })),
      } as never,
      HUMAN.actor,
    );
    const wildcard = { effect: "include", target: { type: "wildcard", value: "*.cliente.example" } };
    const p = (await executeOperation("scope.propose_rule", { rule: wildcard, reason: "la superficie real está en subdominios" }, ctx(MAESTRO))) as { approvalId: string };
    expect(runner.listApprovals().find((a) => a.id === p.approvalId)!.covers).toBe(3);

    await executeOperation("approval.reject", { approvalId: p.approvalId }, ctx(HUMAN));
    expect(((await executeOperation("rules.get", {}, ctx(MAESTRO))) as { noSubdomains: boolean }).noSubdomains).toBe(true);
    await expect(executeOperation("scope.propose_rule", { rule: wildcard, reason: "de nuevo" }, ctx(MAESTRO))).rejects.toMatchObject({ code: "SUBDOMAINS_EXCLUDED" });

    // The exact host is still welcome.
    const www = (await executeOperation("scope.propose_rule", { rule: { effect: "include", target: { type: "domain", value: "www.cliente.example" } }, reason: "el sitio redirige a www" }, ctx(MAESTRO))) as { status: string };
    expect(www.status).toBe("pending_approval");
  });

  it("saving the rules without the flag keeps it", async () => {
    await executeOperation("rules.set", { accounts: [], allowed: "", avoid: "", noSubdomains: true }, ctx(HUMAN));
    await executeOperation("rules.set", { accounts: [], allowed: "solo horario laboral", avoid: "" }, ctx(HUMAN));
    expect(((await executeOperation("rules.get", {}, ctx(HUMAN))) as { noSubdomains: boolean; allowed: string })).toMatchObject({ noSubdomains: true, allowed: "solo horario laboral" });
  });
});

it("a host in scope only on some ports says how to write the target", () => {
  const e = ws.create({ clientName: "Lab", name: "Puertos", mode: "web" }, HUMAN.actor);
  e.addScopeRule({ effect: "include", target: { type: "domain", value: "api.lab.test" }, ports: "443" }, HUMAN.actor);
  const bare = e.checkScope("api.lab.test", "active", { type: "human" });
  expect(bare).toMatchObject({ decision: "deny", code: "OUT_OF_SCOPE" });
  expect("reason" in bare ? bare.reason : "").toMatch(/only on ports 443.*api\.lab\.test:443/);
  expect(e.checkScope("https://api.lab.test/x", "active", { type: "human" }).decision).not.toBe("deny");
});
