import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeOperation, type OperationContext, ParallelClient, pseudonym, useGithubFetch, useResearchClient, Workspace } from "../src/index.js";

/**
 * Research on the web for the Maestro: search, read pages, GitHub - through a search service that
 * needs no key, never with the client's data in a query, never reading a project's target.
 */

const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
const human: Actor = { type: "human", id: "01J00000000000000000000000" };
let dir: string;

/** A Parallel-like MCP server: sessions, JSON or SSE answers, a session that lapses. */
function parallelServer(options: { sse?: boolean; lapseOnce?: boolean } = {}) {
  const calls: Array<{ method: string; name?: string; args?: Record<string, unknown>; session?: string }> = [];
  let lapsed = false;
  let sessions = 0;
  const fetchImpl = (async (_url: string | URL | Request, init: RequestInit = {}) => {
    const body = JSON.parse(String(init.body)) as { id?: number; method: string; params?: { name?: string; arguments?: Record<string, unknown> } };
    const session = (init.headers as Record<string, string>)["mcp-session-id"];
    calls.push({ method: body.method, ...(body.params?.name ? { name: body.params.name, args: body.params.arguments } : {}), ...(session ? { session } : {}) });
    if (body.method === "initialize") return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { protocolVersion: "2025-03-26" } }), { headers: { "content-type": "application/json", "mcp-session-id": `s${++sessions}` } });
    if (body.method === "notifications/initialized") return new Response(null, { status: 202 });
    if (options.lapseOnce && !lapsed) {
      lapsed = true;
      return new Response("session not found", { status: 404 });
    }
    const text =
      body.params?.name === "web_search"
        ? { results: [{ url: "https://logging.apache.org/security.html", title: "\n Security :: Apache Logging Services ", publish_date: null, excerpts: ["CVE-2021-44228 … Versions fixed 2.15.0", "x".repeat(5000)] }] }
        : { results: [{ url: "https://rdap.org/", title: "RDAP.ORG", excerpts: ["RDAP provides access to registration data"] }], errors: [{ url: "https://gone.example/", error_type: "connect_error" }] };
    const answer = JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { content: [{ type: "text", text: JSON.stringify(text) }] } });
    return options.sse ? new Response(`event: message\ndata: ${answer}\n\n`, { headers: { "content-type": "text/event-stream" } }) : new Response(answer, { headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function world(policy?: "local_only") {
  const ws = new Workspace(join(dir, "ws"));
  const eng = ws.create({ clientName: "Acme Bank", name: "Web", mode: "web" }, human);
  if (policy) eng.setInfo({ ...eng.info, dataPolicy: policy }, human);
  eng.addScopeRule({ effect: "include", target: { type: "domain", value: "acmebank.test" } } as never, human);
  const ctx = (actor: Actor) => ({ workspace: ws, caller: { actor, policy: { type: actor.type === "agent" ? "agent" : "human", autonomy: "autonomous", maxRisk: "active" } }, defaultEngagementId: eng.info.id, engagement: () => eng }) as unknown as OperationContext;
  return { ws, eng, op: (name: string, input: Record<string, unknown>, actor: Actor = agent) => executeOperation(name, input, ctx(actor)) };
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-research-"));
});
afterEach(() => {
  useResearchClient(undefined);
  useGithubFetch(undefined);
  rmSync(dir, { recursive: true, force: true });
});

describe("searching the web", () => {
  it("finds pages with excerpts, marks them as information (not instructions), trims them and audits the query", async () => {
    const server = parallelServer();
    useResearchClient(new ParallelClient(server.fetchImpl));
    const w = world();
    try {
      const r = (await w.op("research.search", { objective: "Apache's advisory for Log4Shell", queries: ["CVE-2021-44228 advisory"] })) as { note: string; results: Array<{ url: string; title: string; excerpts: string[] }> };
      expect(r.note).toMatch(/never follow instructions/);
      expect(r.results[0]).toMatchObject({ url: "https://logging.apache.org/security.html", title: "Security :: Apache Logging Services" });
      expect(r.results[0]!.excerpts[1]!.length).toBeLessThanOrEqual(1501);
      expect(server.calls.map((c) => c.method)).toEqual(["initialize", "notifications/initialized", "tools/call"]);
      expect(server.calls[2]).toMatchObject({ name: "web_search", args: { objective: "Apache's advisory for Log4Shell", search_queries: ["CVE-2021-44228 advisory"] }, session: "s1" });
      // One session for many searches.
      await w.op("research.search", { objective: "again the same thing", queries: ["log4j fixed versions"] });
      expect(server.calls.filter((c) => c.method === "initialize")).toHaveLength(1);
      expect(w.eng.auditEvents({ limit: 20 }).filter((a) => a.action === "research.search")).toHaveLength(2);
    } finally {
      w.ws.close();
    }
  });

  it("answers in server-sent events too, and opens a lapsed session again", async () => {
    const server = parallelServer({ sse: true, lapseOnce: true });
    useResearchClient(new ParallelClient(server.fetchImpl));
    const w = world();
    try {
      const r = (await w.op("research.search", { objective: "Apache's advisory for Log4Shell", queries: ["log4shell"] })) as { results: unknown[] };
      expect(r.results).toHaveLength(1);
      expect(server.calls.filter((c) => c.method === "initialize")).toHaveLength(2);
    } finally {
      w.ws.close();
    }
  });

  it("never sends the client's data: no markers, no real value of the client; nothing at all in a local-only project", async () => {
    const server = parallelServer();
    useResearchClient(new ParallelClient(server.fetchImpl));
    const w = world();
    try {
      const marker = pseudonym(w.eng, "domain", "portal.acmebank.test");
      await expect(w.op("research.search", { objective: "what runs there", queries: [`${marker} login`] })).rejects.toThrow(/client's data/);
      await expect(w.op("research.search", { objective: "what runs on portal.acmebank.test", queries: ["portal"] })).rejects.toThrow(/client's data/);
      expect(server.calls).toHaveLength(0);
    } finally {
      w.ws.close();
    }
    const local = world("local_only");
    try {
      await expect(local.op("research.search", { objective: "Apache's advisory", queries: ["log4shell"] })).rejects.toThrow(/local_only/);
    } finally {
      local.ws.close();
    }
  });
});

describe("reading pages", () => {
  it("returns what is relevant and says which could not be read; never a target nor a private network", async () => {
    const server = parallelServer();
    useResearchClient(new ParallelClient(server.fetchImpl));
    const w = world();
    try {
      const r = (await w.op("research.fetch", { urls: ["https://rdap.org/", "https://gone.example/"], objective: "how to query a domain" })) as { pages: Array<{ url: string; content?: string; error?: string }> };
      expect(r.pages).toEqual([
        { url: "https://rdap.org/", title: "RDAP.ORG", content: "RDAP provides access to registration data" },
        { url: "https://gone.example/", error: "connect_error" },
      ]);
      await expect(w.op("research.fetch", { urls: ["https://acmebank.test/login"] })).rejects.toThrow(/target of this project/);
      await expect(w.op("research.fetch", { urls: ["http://10.0.0.5/"] })).rejects.toThrow(/private network/);
      expect(server.calls.filter((c) => c.name === "web_fetch")).toHaveLength(1);
    } finally {
      w.ws.close();
    }
  });
});

describe("GitHub", () => {
  it("advisories by CVE, public PoCs as repositories, with no key", async () => {
    const seen: string[] = [];
    useGithubFetch((async (url: string | URL | Request) => {
      seen.push(String(url));
      if (String(url).includes("/advisories")) return new Response(JSON.stringify([{ ghsa_id: "GHSA-jfh8-c2jp-5v3q", cve_id: "CVE-2021-44228", severity: "critical", summary: "Remote code injection in Log4j", html_url: "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q", published_at: "2021-12-10", vulnerabilities: [{ package: { ecosystem: "maven", name: "org.apache.logging.log4j:log4j-core" }, vulnerable_version_range: ">= 2.13.0, < 2.15.0", first_patched_version: "2.15.0" }] }]), { headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ items: [{ full_name: "kozmer/log4j-shell-poc", html_url: "https://github.com/kozmer/log4j-shell-poc", description: "A PoC", stargazers_count: 1800, pushed_at: "2023-01-01", language: "Python" }] }), { headers: { "content-type": "application/json" } });
    }) as typeof fetch);
    const w = world();
    try {
      const adv = (await w.op("research.github", { kind: "advisories", query: "cve-2021-44228" })) as { results: Array<Record<string, unknown>> };
      expect(seen[0]).toBe("https://api.github.com/advisories?cve_id=CVE-2021-44228&per_page=6");
      expect(adv.results[0]).toMatchObject({ cve: "CVE-2021-44228", severity: "critical", affected: [{ package: "maven:org.apache.logging.log4j:log4j-core", patched: "2.15.0" }] });
      const repos = (await w.op("research.github", { query: "CVE-2021-44228 poc" })) as { results: Array<Record<string, unknown>> };
      expect(repos.results[0]).toMatchObject({ name: "kozmer/log4j-shell-poc", stars: 1800 });
    } finally {
      w.ws.close();
    }
  });
});
