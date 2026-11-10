import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, expect, it } from "vitest";
import { type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/** Exact versions come from reliable sources (headers, generator meta, WordPress files), not a guess. */

const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let origin: string;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-versions-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Versions", mode: "web" }, agent);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
  server = createServer((req, res) => {
    if (req.url === "/") {
      res.writeHead(200, { "Content-Type": "text/html", Server: "nginx/1.18.0 (Ubuntu)", "X-Powered-By": "PHP/8.1.2" });
      return res.end('<!doctype html><meta name="generator" content="WordPress 6.4.2"><link href="/wp-content/plugins/elementor/assets/css/frontend.min.css?ver=4.9.9"><script src="/wp-content/plugins/akismet/x.js"></script>');
    }
    if (req.url === "/wp-content/plugins/elementor/readme.txt") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      return res.end("=== Elementor ===\nStable tag: 3.18.0\nRequires at least: 6.0\n");
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  origin = `http://127.0.0.1:${port}`;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, agent);
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

it("reads versions from headers, the generator meta and a plugin's readme (not the ?ver=)", async () => {
  const r = (await executeOperation("web.detect_versions", { origin }, ctx())) as { status: string; found: Array<{ product: string; version: string; source: string }> };
  expect(r.status).toBe("done");
  const by = Object.fromEntries(r.found.map((f) => [f.product.toLowerCase(), f]));
  expect(by["nginx"]?.version).toBe("1.18.0");
  expect(by["php"]?.version).toBe("8.1.2");
  expect(by["wordpress"]?.version).toBe("6.4.2");
  // The real Elementor version from readme.txt (3.18.0), not the ?ver=4.9.9 cache-buster.
  expect(by["elementor"]?.version).toBe("3.18.0");
  expect(by["elementor"]?.source).toMatch(/readme/);
  // They are registered as technologies for the lookup.
  const techEntities = eng.query({ kind: "technology", limit: 50 });
  const techs = techEntities.map((t) => String(t.attributes.product).toLowerCase());
  expect(techs).toEqual(expect.arrayContaining(["nginx", "php", "wordpress", "elementor"]));
  // The distro in the Server banner is captured, so vuln_lookup can be backport-aware.
  expect(techEntities.every((t) => t.attributes.distro === "ubuntu")).toBe(true);
});
