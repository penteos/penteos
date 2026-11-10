import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { cdnOf, type Engagement, ToolRegistry, ToolRunner, type ToolCaller, Workspace } from "../src/index.js";

/**
 * Agents do not port-scan a CDN: the scan measures Cloudflare, not the client. Names are under the
 * reserved .test domain and allowed runs are cancelled at once, so no real host is ever scanned.
 */

const HUMAN: ToolCaller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" }, origin: "runner" };
const MAESTRO: ToolCaller = { actor: { type: "agent", id: "01JA000000000000000000MSTR" }, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" }, origin: "agent_tool" };

let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-cdn-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Cliente", name: "Web", mode: "web" }, HUMAN.actor);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
  eng.addScopeRule({ effect: "include", target: { type: "wildcard", value: "*.cliente.test" } }, HUMAN.actor);
  eng.addScopeRule({ effect: "include", target: { type: "cidr", value: "104.21.0.0/16" } }, HUMAN.actor);
  // www resolves only to Cloudflare; mail to the client's own server.
  eng.ingest(
    {
      format: "penteos.ingest/v0",
      source: { parser: "test@0.1", tool: "dnsx" },
      rawIds: [],
      observedAt: new Date().toISOString(),
      items: [
        { op: "relate", type: "resolves_to", from: { kind: "domain", key: { fqdn: "www.cliente.test" } }, to: { kind: "host", key: { ip: "104.21.18.129" } } },
        { op: "relate", type: "resolves_to", from: { kind: "domain", key: { fqdn: "mail.cliente.test" } }, to: { kind: "host", key: { ip: "198.51.100.3" } } },
      ],
    } as never,
    HUMAN.actor,
  );
});

afterEach(() => {
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

it("knows Cloudflare's addresses", () => {
  expect(cdnOf("104.21.18.129")).toBe("Cloudflare");
  expect(cdnOf("172.67.181.217")).toBe("Cloudflare");
  expect(cdnOf("2606:4700::6815:1281")).toBe("Cloudflare");
  expect(cdnOf("198.51.100.3")).toBeUndefined();
  expect(cdnOf("not-an-ip")).toBeUndefined();
});

it("refuses an agent's nmap on names or addresses behind the CDN, with what to do instead", () => {
  for (const target of ["www.cliente.test", "104.21.18.129"]) {
    const r = runner.runNmap(["-sV", "--top-ports", "100", target], MAESTRO);
    expect(r).toMatchObject({ status: "denied", code: "CDN_TARGET" });
    expect((r as { reason: string }).reason).toMatch(/Cloudflare.*httpx/s);
  }
});

it("lets the same agent scan the client's own server, and the operator scan anything", async () => {
  for (const [target, caller] of [["mail.cliente.test", MAESTRO], ["www.cliente.test", HUMAN]] as const) {
    const r = runner.runNmap(["-sV", "--top-ports", "100", target], caller);
    expect(r.status).not.toBe("denied");
    if ("run" in r && r.run) {
      runner.cancel(r.run.id);
      await runner.waitForRun(r.run.id, 10);
    }
  }
});

it("refuses an agent's sweep of every nuclei template behind the CDN; a chosen check goes on", async () => {
  const sweep = await runner.runExec({ argv: ["nuclei", "-silent", "-u", "https://www.cliente.test"], targets: ["https://www.cliente.test"], risk: "active" }, MAESTRO);
  expect(sweep).toMatchObject({ status: "denied", code: "CDN_TARGET" });
  expect((sweep as { reason: string }).reason).toMatch(/Cloudflare.*-tags/s);
  // Templates chosen: past this rule (where nuclei is installed it starts against a .test name, which never resolves, and is stopped at once).
  const stop = async (r: unknown) => {
    const run = (r as { run?: { id: string } }).run;
    if (run) {
      runner.cancel(run.id);
      await runner.waitForRun(run.id, 10);
    }
  };
  const chosen = await runner.runExec({ argv: ["nuclei", "-silent", "-u", "https://www.cliente.test", "-tags", "nextjs"], targets: ["https://www.cliente.test"], risk: "active" }, MAESTRO);
  expect((chosen as { code?: string }).code).not.toBe("CDN_TARGET");
  await stop(chosen);
  // The client's own server, and the operator by hand: not this rule's business.
  const own = await runner.runExec({ argv: ["nuclei", "-silent", "-u", "https://mail.cliente.test"], targets: ["https://mail.cliente.test"], risk: "active" }, MAESTRO);
  expect((own as { code?: string }).code).not.toBe("CDN_TARGET");
  await stop(own);
  const human = await runner.runExec({ argv: ["nuclei", "-silent", "-u", "https://www.cliente.test"], targets: ["https://www.cliente.test"], risk: "active" }, HUMAN);
  expect((human as { code?: string }).code).not.toBe("CDN_TARGET");
  await stop(human);
});
