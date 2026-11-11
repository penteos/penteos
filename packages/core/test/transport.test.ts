import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Caller, CertificateAuthority, type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";
import { certificateIssues, clientHello, cookieIssues, corsIssue, headerIssues, parseServerHello } from "../src/transport.js";

/**
 * How a site protects the connection. What a real assessment found on a payments site and Penteos
 * did not check: TLS 1.0/1.1 and 3DES accepted, plain HTTP with no redirect, no HSTS, a cookie
 * without Secure. The handshakes are built by hand (OpenSSL 3 cannot offer 3DES or RC4).
 */
describe("the pieces", () => {
  it("builds a ClientHello for exactly one version, and reads the server's answer", () => {
    const hello = clientHello("pagos.example", "TLSv1.0", [0x000a]);
    expect(hello[0]).toBe(0x16); // handshake record
    expect(hello[5]).toBe(0x01); // ClientHello
    expect(hello.readUInt16BE(9)).toBe(0x0301); // TLS 1.0 offered
    expect(hello.includes(Buffer.from("pagos.example"))).toBe(true); // SNI
    // ServerHello: TLS 1.0, empty session id, cipher 0x000a (3DES).
    const body = Buffer.concat([Buffer.from([0x03, 0x01]), Buffer.alloc(32), Buffer.from([0x00, 0x00, 0x0a, 0x00])]);
    const sh = Buffer.concat([Buffer.from([0x16, 0x03, 0x01, 0x00, body.length + 4, 0x02, 0x00, 0x00, body.length]), body]);
    expect(parseServerHello(sh)).toEqual({ kind: "hello", version: 0x0301, cipher: 0x000a });
    expect(parseServerHello(Buffer.from([0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28]))).toEqual({ kind: "alert" });
  });

  it("reads the headers' defences, cookies and CORS", () => {
    const keys = (h: Array<[string, string]>) => headerIssues(h, true).map((i) => i.key);
    expect(keys([["content-type", "text/html"]])).toEqual(["hsts", "csp", "framing", "nosniff"]);
    expect(keys([["strict-transport-security", "max-age=31536000"], ["content-security-policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'"], ["x-frame-options", "DENY"], ["x-content-type-options", "nosniff"]])).toEqual(["csp:unsafe-inline", "csp:unsafe-eval"]);
    // A nonce makes browsers ignore 'unsafe-inline': not a problem then.
    expect(keys([["strict-transport-security", "max-age=31536000"], ["content-security-policy", "script-src 'nonce-abc' 'unsafe-inline'; frame-ancestors 'none'"], ["x-content-type-options", "nosniff"]])).toEqual([]);
    expect(cookieIssues(["session=abc; Path=/"], true).map((i) => `${i.key}:${i.severity}`)).toEqual(["cookie:session:secure:medium", "cookie:session:httponly:low", "cookie:session:samesite:info"]);
    expect(corsIssue("https://evil.test", [["access-control-allow-origin", "https://evil.test"], ["access-control-allow-credentials", "true"]])?.severity).toBe("high");
    expect(corsIssue("https://evil.test", [["access-control-allow-origin", "*"]])).toBeUndefined();
    expect(certificateIssues("a.test", { authorized: true, cert: { valid_to: "Jan 1 00:00:00 2020 GMT" } as never }, new Date("2026-01-01"))[0]!.key).toBe("cert:expired");
  });
});

const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let port: number;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-transport-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "TLS", mode: "web" }, HUMAN.actor);
  const ca = await CertificateAuthority.load(join(dir, "ca"));
  const { cert, key } = await ca.pemFor("localhost");
  server = createServer({ cert, key, minVersion: "TLSv1.2" }, (req, res) => {
    const origin = req.headers.origin;
    res.writeHead(200, { "content-type": "text/html", "set-cookie": "session=abc123; Path=/", ...(origin ? { "access-control-allow-origin": origin, "access-control-allow-credentials": "true" } : {}) });
    res.end("<html>pagos</html>");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  port = (server.address() as { port: number }).port;
  eng.addScopeRule({ effect: "include", target: { type: "url", value: `https://localhost:${port}` } }, HUMAN.actor);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
});
afterEach(async () => {
  await new Promise((r) => server.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

it("checks a whole site: old TLS refused here, missing defences and CORS with credentials reported, plain HTTP left alone when out of scope", async () => {
  const r = (await executeOperation("web.check_transport", { target: `https://localhost:${port}` }, { workspace: ws, caller: HUMAN, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner } as unknown as OperationContext)) as { issues: string[]; rawId: string };
  expect(r.issues.join("\n")).not.toMatch(/TLSv1\.0 accepted|SSLv3 accepted|3DES/); // the server only speaks TLS 1.2
  expect(r.issues).toEqual(expect.arrayContaining(["low: No HSTS (Strict-Transport-Security)", "medium: Cookie session without Secure", "high: CORS trusts any origin with credentials"]));
  const log = eng.readRaw(r.rawId).toString();
  expect(log).toMatch(/TLSv1\.2 \(broad ciphers\): accepted/);
  expect(log).toMatch(/TLSv1\.0: refused|TLSv1\.0: [a-z]/);
  expect(log).toMatch(/plain HTTP: not checked \(http:\/\/localhost is not in scope\)/);
  expect(eng.query({ kind: "observation", limit: 50 }).some((o) => o.attributes.sourceRule === "transport:cors:reflect:creds")).toBe(true);
});
