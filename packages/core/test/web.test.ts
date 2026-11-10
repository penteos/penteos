import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

const human: Actor = { type: "human", id: "01JA0000000000000000000HMN" };
const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };

let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let origin: string;
let lastRequest = "";

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-web-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Web", mode: "web" }, human);
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      lastRequest = `${req.method} ${req.url} cookie=${req.headers.cookie ?? ""} body=${body}`;
      res.writeHead(req.url?.startsWith("/login") ? 302 : 200, { "Content-Type": "text/html", "Set-Cookie": "PHPSESSID=s3cr3tvalue; path=/" });
      res.end(`<h1>hola ${req.url}</h1>`);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  origin = `http://127.0.0.1:${port}`;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, human);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
});

afterEach(async () => {
  await new Promise((r) => server.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const ctx = (actor: Actor): OperationContext => ({
  workspace: ws,
  caller: { actor, policy: actor.type === "agent" ? { type: "agent", autonomy: "autonomous", maxRisk: "active" } : { type: "human" } },
  defaultEngagementId: eng.info.id,
  engagement: () => eng,
  runner: () => runner,
});

describe("http.send", () => {
  it("sends a raw request in scope, keeps the exchange and maps the endpoint with its parameters", async () => {
    await executeOperation("secret.save", { name: "app_session", kind: "cookie", value: "PHPSESSID=s3cr3tvalue" }, ctx(agent));
    const r = (await executeOperation(
      "http.send",
      { origin, raw: "POST /login.php?next=/home HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\nCookie: {{secret:app_session}}\n\nusername=admin&password=x" },
      ctx(agent),
    )) as { status: string; rawId: string; response: { status: number; headers: { content: string } } };
    expect(r.status).toBe("done");
    expect(r.response.status).toBe(302);
    expect(lastRequest).toBe("POST /login.php?next=/home cookie=PHPSESSID=s3cr3tvalue body=username=admin&password=x");
    // The agent never sees the cookie value, even when the target sends it back.
    expect(JSON.stringify(r)).not.toContain("s3cr3tvalue");
    expect(eng.readRaw(r.rawId).toString()).toContain("HTTP/1.1 302");

    const ep = eng.query({ kind: "endpoint" })[0]!;
    expect(ep.attributes).toMatchObject({ pathTemplate: "/login.php", methods: ["POST"], statusesSeen: [302] });
    expect(ep.attributes.params).toEqual(expect.arrayContaining([{ name: "next", location: "query" }, { name: "username", location: "body" }]));
  });

  it("is checked against the scope like any other action", async () => {
    await expect(executeOperation("http.send", { origin: "http://example.com", raw: "GET / HTTP/1.1" }, ctx(agent))).rejects.toMatchObject({ code: "OUT_OF_SCOPE" });
    await expect(executeOperation("http.send", { origin, raw: "garbage" }, ctx(agent))).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
  });
});

describe("web imports and coverage", () => {
  it("imports a HAR and a Burp export into applications and endpoints", async () => {
    const har = { log: { entries: [
      { request: { method: "GET", url: "https://shop.example/api/users/12?expand=1", headers: [] }, response: { status: 200, headers: [], content: { text: "{}" } } },
      { request: { method: "POST", url: "https://shop.example/api/login", headers: [], postData: { mimeType: "application/json", text: '{"user":"a","pass":"b"}' } }, response: { status: 401, headers: [] } },
    ] } };
    const r1 = (await executeOperation("ingest.import", { filename: "h.har", contentBase64: Buffer.from(JSON.stringify(har)).toString("base64") }, ctx(human))) as { format: string; exchanges: number };
    expect(r1).toMatchObject({ format: "har", exchanges: 2 });
    const burp = `<?xml version="1.0"?><items burpVersion="2024.1"><item><url><![CDATA[https://shop.example/cart?id=3]]></url><method><![CDATA[GET]]></method><status>200</status><request base64="true"><![CDATA[${Buffer.from("GET /cart?id=3 HTTP/1.1\r\nHost: shop.example\r\n\r\n").toString("base64")}]]></request><response base64="true"><![CDATA[${Buffer.from("HTTP/1.1 200 OK\r\n\r\nok").toString("base64")}]]></response></item></items>`;
    expect(await executeOperation("ingest.import", { filename: "b.xml", contentBase64: Buffer.from(burp).toString("base64") }, ctx(human))).toMatchObject({ format: "burp", exchanges: 1 });

    const paths = eng.query({ kind: "endpoint" }).map((e) => e.attributes.pathTemplate).sort();
    expect(paths).toEqual(["/api/login", "/api/users/{id}", "/cart"]);
    const login = eng.query({ kind: "endpoint" }).find((e) => e.attributes.pathTemplate === "/api/login")!;
    expect(login.attributes.params).toEqual([{ name: "user", location: "body" }, { name: "pass", location: "body" }]);

    const app = eng.query({ kind: "webapp" })[0]!;
    await executeOperation("webapp.set_coverage", { webappId: app.id, category: "ATHN", status: "vulnerable", note: "credenciales por defecto" }, ctx(agent));
    const cov = (await executeOperation("webapp.coverage", { webappId: app.id }, ctx(human))) as Array<{ id: string; status: string }>;
    expect(cov.find((c) => c.id === "ATHN")!.status).toBe("vulnerable");
    expect(cov.find((c) => c.id === "INPV")!.status).toBe("untested");
  });

  it("katana results become endpoints", async () => {
    const tool = join(dir, "katana");
    writeFileSync(tool, `#!/bin/sh\necho '{"request":{"method":"get","endpoint":"${origin}/vulnerabilities/sqli/?id=1"},"response":{"status_code":200}}'\n`);
    chmodSync(tool, 0o755);
    const builtin = runner.registry.get("katana")!;
    runner.registry.save({ ...builtin, binaries: [tool], identity: undefined } as never);
    const r = (await executeOperation("run.exec", { argv: ["katana", "-u", `${origin}/`], targets: [], risk: "active", wait: 5 }, ctx(human))) as { status: string };
    expect(r.status).toBe("finished");
    expect(eng.query({ kind: "endpoint" })[0]!.attributes).toMatchObject({ pathTemplate: "/vulnerabilities/sqli", methods: ["GET"], statusesSeen: [200] });
  });
});
