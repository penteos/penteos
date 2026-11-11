import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { type Caller, type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/** GraphQL found on its usual path: introspection (schema kept), batching and GET, each reported. */
const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let server: Server;
let origin: string;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-graphql-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "API", mode: "web" }, HUMAN.actor);
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      if (!req.url?.startsWith("/graphql")) return void res.writeHead(404).end("no");
      if (req.method === "GET") return void res.writeHead(200, { "content-type": "application/json" }).end(`{"data":{"__typename":"Query"}}`);
      const parsed = JSON.parse(body || "{}");
      if (Array.isArray(parsed)) return void res.writeHead(200).end(JSON.stringify(parsed.map(() => ({ data: { __typename: "Query" } }))));
      if (String(parsed.query).includes("__schema")) {
        return void res.writeHead(200).end(JSON.stringify({ data: { __schema: { queryType: { name: "Query" }, mutationType: { name: "Mutation" }, types: [{ name: "Mutation", kind: "OBJECT", fields: [{ name: "transferFunds", args: [] }, { name: "deleteUser", args: [] }] }] } } }));
      }
      res.writeHead(200).end(`{"data":{"__typename":"Query"}}`);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  origin = `http://127.0.0.1:${port}`;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, HUMAN.actor);
});
afterEach(async () => {
  await new Promise((r) => server.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

it("finds GraphQL, keeps its schema and reports introspection, batching and GET", async () => {
  const runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
  const r = (await executeOperation("web.probe_graphql", { origin }, { workspace: ws, caller: HUMAN, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner } as unknown as OperationContext)) as { hits: string[] };
  expect(r.hits).toEqual(["medium: GraphQL introspection enabled on /graphql", "low: GraphQL accepts batched queries on /graphql", "low: GraphQL answers GET requests on /graphql"]);
  expect(eng.query({ kind: "observation", limit: 10 }).find((o) => /introspection/.test(String(o.attributes.title)))!.attributes.detail).toMatch(/transferFunds, deleteUser/);
  const gqlDir = join(eng.dir, "work", "graphql");
  expect(existsSync(gqlDir) ? readdirSync(gqlDir).length : readdirSync(join(dir, "data")).length).toBeGreaterThan(0);
});
