import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { CertificateAuthority, DEFAULT_PROXY_SETTINGS, PenteosProxy, Workspace } from "../src/index.js";

/** A taken port never leaves the operator without a proxy, and the move is said (plan-instalacion-linux, D5). */

const cleanup: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  for (const c of cleanup.splice(0).reverse()) await c();
});

const listen = (port: number) =>
  new Promise<Server>((resolve, reject) => {
    const s = createServer();
    s.once("error", reject);
    s.listen(port, "127.0.0.1", () => resolve(s));
  });

it("moves to the next free port when the one asked for is taken, and says so", async () => {
  const dir = mkdtempSync(join(tmpdir(), "penteos-port-"));
  const ws = new Workspace(join(dir, "data"));
  cleanup.push(() => {
    ws.close();
    rmSync(dir, { recursive: true, force: true });
  });
  // A free port P where P+1 is free too, then something else takes P.
  const probe = await listen(0);
  const wanted = (probe.address() as { port: number }).port;
  await new Promise((r) => probe.close(r));
  const taker = await listen(wanted);
  cleanup.push(() => new Promise<void>((r) => taker.close(() => r())));
  const proxy = new PenteosProxy(ws, await CertificateAuthority.load(join(dir, "ca")), { token: "t", actor: { type: "human", id: "01JA0000000000000000000HMN" }, settings: () => DEFAULT_PROXY_SETTINGS });
  cleanup.push(() => proxy.close());
  const port = await proxy.start(wanted);
  expect(port).not.toBe(wanted);
  expect(port).toBeGreaterThan(wanted);
  expect(port).toBeLessThanOrEqual(wanted + 10);
  expect(proxy.requestedPort).toBe(wanted);
});
