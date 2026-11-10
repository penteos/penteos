import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterAll, beforeAll, expect, it } from "vitest";
import { type ChangeEvent, closeAllOob, type Engagement, executeOperation, findInteractsh, isPublicServer, type OperationContext, Workspace } from "../src/index.js";

/**
 * Out-of-band interactions end to end, against the public interactsh server oast.fun: register a
 * test, make the "target" contact the host, and check the interaction arrives as evidence and an
 * event. Skipped where interactsh-client is missing or there is no network.
 */

const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
const has = Boolean(findInteractsh());
let online = false;
let dir: string;
let ws: Workspace;
let eng: Engagement;
const events: ChangeEvent[] = [];

beforeAll(async () => {
  if (has) {
    try {
      execFileSync("getent", ["hosts", "oast.fun"], { timeout: 5000, stdio: "ignore" });
      online = true;
    } catch {
      online = false;
    }
  }
  dir = mkdtempSync(join(tmpdir(), "penteos-oob-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "OOB", mode: "web" }, agent);
  eng.events.on("change", (e: ChangeEvent) => events.push(e));
});

afterAll(() => {
  closeAllOob();
  ws?.close();
  rmSync(dir, { recursive: true, force: true });
}, 30_000);

const ctx = (): OperationContext =>
  ({ workspace: ws, caller: { actor: agent, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } }, defaultEngagementId: eng.info.id, engagement: () => eng }) as unknown as OperationContext;

const runnable = has && online;

it.skipIf(!runnable)("records a target's callback as evidence and tells the agent", async () => {
  const r = (await executeOperation("oob.new", { purpose: "SSRF en el campo url de POST /api/import", target: "POST /api/import" }, ctx())) as { status: string; address: string; tag: string };
  expect(r.status).toBe("ready");
  expect(r.address).toMatch(/^o[0-9a-f]{10}\.[a-z0-9]+\.oast\.fun$/);

  // The "target" contacts the host (what a vulnerable server would do with our payload).
  try {
    execFileSync("curl", ["-s", "-m", "8", `http://${r.address}/ssrf`], { timeout: 10_000, stdio: "ignore" });
  } catch {
    /* the lookup/request itself is the interaction; curl's own result does not matter */
  }

  // The interaction travels back over the public server; give it a moment.
  const hit = await waitFor(() => (executeOperation("oob.check", { tag: r.tag }, ctx()) as Promise<{ interactions: unknown[] }>).then((c) => c.interactions.length > 0), 25_000);
  expect(hit).toBe(true);

  const check = (await executeOperation("oob.check", { tag: r.tag }, ctx())) as { interactions: Array<{ protocol: string; rawId?: string; purpose?: string }> };
  const i = check.interactions[0]!;
  expect(["dns", "http"]).toContain(i.protocol);
  expect(i.purpose).toContain("SSRF");
  expect(i.rawId).toMatch(/^sha256:/);
  // It is a real raw artifact, citable as evidence.
  expect(eng.readRaw(i.rawId!).length).toBeGreaterThan(0);
  // The agent that asked heard it.
  expect(events.some((e) => e.type === "oob.interaction" && e.tag === r.tag)).toBe(true);
}, 60_000);

it("knows which interaction servers are public", () => {
  expect(isPublicServer("oast.fun")).toBe(true);
  expect(isPublicServer("OAST.PRO")).toBe(true);
  expect(isPublicServer("oob.mi-empresa.example")).toBe(false);
});

it.skipIf(!runnable)("a public server is flagged as leaking to a third party", async () => {
  const r = (await executeOperation("oob.enable", { server: "oast.fun" }, ctx())) as { note: string };
  expect(r.note).toMatch(/third party/i);
}, 40_000);

async function waitFor(check: () => Promise<boolean>, timeoutMs: number): Promise<boolean> {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    if (await check()) return true;
    await new Promise((r) => setTimeout(r, 1500));
  }
  return false;
}
