import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  type Engagement,
  executeOperation,
  installCommand,
  manifestTargets,
  type OperationContext,
  parseWithManifest,
  ToolRegistry,
  ToolRunner,
  validateManifest,
  Workspace,
} from "../src/index.js";

const registry = new ToolRegistry();
const get = (name: string) => registry.get(name)!;
const opts = { rawIds: [], observedAt: "2026-10-13T12:00:00.000Z" };

describe("built-in manifests", () => {
  it("are all valid", () => {
    expect(registry.all().length).toBeGreaterThanOrEqual(10);
  });

  it("subfinder: one domain per JSON line", () => {
    const out = '{"host":"api.acme.test","input":"acme.test","source":"crtsh"}\n{"host":"WWW.acme.test","input":"acme.test","source":"dnsdumpster"}\n';
    const { batch } = parseWithManifest(get("subfinder"), out, opts);
    expect(batch.items).toEqual([
      { op: "upsert", kind: "domain", key: { fqdn: "api.acme.test" } },
      { op: "upsert", kind: "domain", key: { fqdn: "www.acme.test" } },
    ]);
    expect(batch.source.parser).toBe("manifest:subfinder@0.1.0");
  });

  it("dig: A records resolve, CNAMEs alias, MX/NS/TXT become records", () => {
    const out = [
      "; <<>> DiG 9.18 <<>> +noall +answer acme.test",
      "acme.test.\t\t300\tIN\tA\t203.0.113.1",
      "www.acme.test.\t300\tIN\tCNAME\tcname.vercel-dns.com.",
      'acme.test.\t\t300\tIN\tTXT\t"v=spf1 include:_spf.protonmail.ch ~all"',
      "acme.test.\t\t300\tIN\tMX\t10 mail.protonmail.ch.",
    ].join("\n");
    const { batch } = parseWithManifest(get("dig"), out, opts);
    expect(batch.items).toContainEqual({ op: "upsert", kind: "host", key: { ip: "203.0.113.1" }, attributes: { status: "unknown" } });
    expect(batch.items).toContainEqual({
      op: "relate",
      type: "resolves_to",
      from: { kind: "domain", key: { fqdn: "acme.test" } },
      to: { kind: "host", key: { ip: "203.0.113.1" } },
    });
    expect(batch.items).toContainEqual({
      op: "relate",
      type: "alias_of",
      from: { kind: "domain", key: { fqdn: "www.acme.test" } },
      to: { kind: "domain", key: { fqdn: "cname.vercel-dns.com" } },
    });
    expect(batch.items).toContainEqual({
      op: "upsert",
      kind: "domain",
      key: { fqdn: "acme.test" },
      attributes: { records: [{ type: "MX", value: "10 mail.protonmail.ch.", observedAt: "2026-10-13T12:00:00.000Z" }] },
    });
  });

  it("httpx: webapp, domain, service, technologies and redirects", () => {
    const line = JSON.stringify({
      url: "https://acme.test",
      input: "acme.test",
      title: "Acme",
      webserver: "Vercel",
      tech: ["HSTS", "Vercel"],
      host: "203.0.113.1",
      port: "443",
      status_code: 307,
      location: "https://www.acme.test/",
    });
    const { batch, skipped } = parseWithManifest(get("httpx"), line, opts);
    expect(skipped).toBe(0);
    expect(batch.items).toContainEqual({ op: "upsert", kind: "webapp", key: { origin: "https://acme.test" }, attributes: { title: "Acme" }, confidence: 0.9 });
    expect(batch.items).toContainEqual(
      expect.objectContaining({ op: "upsert", kind: "service", key: { ip: "203.0.113.1", transport: "tcp", port: 443 } }),
    );
    expect(batch.items).toContainEqual({
      op: "upsert",
      kind: "webapp",
      key: { origin: "https://acme.test" },
      attributes: { technologies: [{ name: "Vercel", confidence: 0.8 }] },
    });
    expect(batch.items).toContainEqual(expect.objectContaining({ op: "observe", title: "Redirects to https://www.acme.test/", sourceRule: "httpx:redirect" }));
  });

  it("nuclei: one observation per match, with severity and location", () => {
    const line = JSON.stringify({
      "template-id": "missing-csp",
      info: { name: "Missing Content-Security-Policy", severity: "info", description: "No CSP header" },
      type: "http",
      host: "https://acme.test",
      "matched-at": "https://acme.test/login",
    });
    const { batch } = parseWithManifest(get("nuclei"), line, opts);
    expect(batch.items).toEqual([
      {
        op: "observe",
        title: "Missing Content-Security-Policy",
        sourceRule: "nuclei:missing-csp",
        affects: [{ kind: "webapp", key: { origin: "https://acme.test" } }],
        severityHint: "info",
        detail: "No CSP header",
        location: "https://acme.test/login",
      },
    ]);
  });

  it("curl: values of data and header options are not targets; address overrides still are", () => {
    const curl = get("curl");
    const argv = ["-s", "-X", "POST", "http://lab.acme.test:8080/scriptText", "--data-urlencode", "script=println('id')", "--header", "X-Test: 1", "--json", '{"a":1}', "--form", "f=@x.txt"];
    expect(manifestTargets(curl, argv).targets).toEqual(["http://lab.acme.test:8080/scriptText"]);
    // --resolve sends the request elsewhere: its value stays a target, so the scope check sees it.
    expect(manifestTargets(curl, ["--resolve", "lab.acme.test:443:198.51.100.7", "https://lab.acme.test/"]).targets).toContain("lab.acme.test:443:198.51.100.7");
  });

  it("curl: headers and robots.txt mapped against the run's target", () => {
    const out = [
      "HTTP/2 401",
      "Server: nginx",
      'www-authenticate: Basic realm="Laboratorio Acme"',
      "content-security-policy: default-src 'self'; connect-src https://api.acme.test",
      "",
      "User-agent: *",
      "Disallow: /admin",
    ].join("\n");
    const { batch } = parseWithManifest(get("curl"), out, { ...opts, vars: { target: "https://lab.acme.test/" } });
    expect(batch.items).toContainEqual({ op: "upsert", kind: "webapp", key: { origin: "https://lab.acme.test" } });
    expect(batch.items).toContainEqual({
      op: "upsert",
      kind: "webapp",
      key: { origin: "https://lab.acme.test" },
      attributes: { technologies: [{ name: "nginx", confidence: 0.7 }] },
    });
    expect(batch.items).toContainEqual(expect.objectContaining({ op: "observe", title: 'Requests HTTP authentication: Basic realm="Laboratorio Acme"' }));
    expect(batch.items).toContainEqual(expect.objectContaining({ op: "observe", sourceRule: "http:csp", detail: "default-src 'self'; connect-src https://api.acme.test" }));
    expect(batch.items).toContainEqual({ op: "upsert", kind: "endpoint", key: { origin: "https://lab.acme.test", path: "/admin" } });
  });

  it("skips lines it cannot map instead of failing the whole batch", () => {
    const out = '{"host":"ok.acme.test"}\n{"host":"not a domain!"}\nnot json\n';
    const { batch, skipped } = parseWithManifest(get("subfinder"), out, opts);
    expect(batch.items).toHaveLength(1);
    expect(skipped).toBe(1);
  });
});

describe("targets from arguments", () => {
  it("reads flag and positional targets, ignoring non-target words", () => {
    expect(manifestTargets(get("dig"), ["+noall", "+answer", "acme.test", "MX", "@1.1.1.1"]).targets).toEqual(["acme.test"]);
    expect(manifestTargets(get("httpx"), ["-u", "https://a.acme.test,https://b.acme.test", "-title"]).targets).toEqual([
      "https://a.acme.test",
      "https://b.acme.test",
    ]);
    expect(manifestTargets(get("netexec"), ["smb", "10.0.0.5", "-u", "admin"]).targets).toEqual(["10.0.0.5"]);
  });

  it("flags commands whose targets come from a file", () => {
    expect(manifestTargets(get("httpx"), ["-l", "hosts.txt"]).unchecked).toMatch(/file/);
  });
});

describe("install recipes per distribution", () => {
  it("uses the right package name for each package manager", () => {
    expect(installCommand(get("dig"), "apt")).toBe("sudo apt install dnsutils");
    expect(installCommand(get("dig"), "pacman")).toBe("sudo pacman -S --needed bind");
    expect(installCommand(get("dig"), "dnf")).toBe("sudo dnf install bind-utils");
    expect(installCommand(get("dig"), "brew")).toBe("brew install bind");
    expect(installCommand(get("httpx"), "pacman")).toBe("go install github.com/projectdiscovery/httpx/cmd/httpx@latest");
  });

  it("has no recipe when the distribution does not package the tool", () => {
    expect(installCommand(get("whatweb"), "pacman")).toBeUndefined();
  });
});

describe("manifest validation", () => {
  it("rejects regexes that do not compile and unknown fields shapes", () => {
    expect(() =>
      validateManifest({ name: "x", description: "x", binaries: ["x"], risk: "passive", output: { format: "lines", rules: [{ match: "(", emit: [] }] } }),
    ).toThrow();
    expect(() => validateManifest({ name: "Bad Name", description: "x", binaries: ["x"], risk: "passive" })).toThrow();
  });
});

describe("teaching Penteos a new tool at runtime", () => {
  const human: Actor = { type: "human", id: "01JA0000000000000000000000" };
  const agent: Actor = { type: "agent", id: "01JA0000000000000000000001" };
  let dir: string;
  let ws: Workspace;
  let eng: Engagement;
  let runner: ToolRunner;
  let tool: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "penteos-manifest-"));
    ws = new Workspace(join(dir, "data"));
    eng = ws.create({ clientName: "Cliente", name: "Web", mode: "web" }, human);
    eng.addScopeRule({ effect: "include", target: { type: "wildcard", value: "*.cliente.example" } }, human);
    runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
    // A tool Penteos has never heard of: it prints JSON lines with the hosts it found.
    tool = join(dir, "fakeprobe");
    writeFileSync(tool, '#!/bin/sh\necho \'{"found":"api.cliente.example"}\'\necho \'{"found":"dev.cliente.example"}\'\n');
    chmodSync(tool, 0o755);
  });

  afterEach(() => {
    ws.close();
    rmSync(dir, { recursive: true, force: true });
  });

  function ctx(actor: Actor): OperationContext {
    return {
      workspace: ws,
      caller: { actor, policy: actor.type === "agent" ? { type: "agent", autonomy: "autonomous", maxRisk: "active" } : { type: "human" } },
      defaultEngagementId: eng.info.id,
      engagement: () => eng,
      runner: () => runner,
    };
  }

  it("an agent writes a manifest, tests it, a human approves it, and the tool's output lands in the graph", async () => {
    const manifest = {
      name: "fakeprobe",
      description: "Finds subdomains",
      binaries: [tool],
      risk: "passive",
      targets: { flags: ["-d"] },
      invoke: { perTarget: ["-d", "{{target}}"] },
      output: { format: "jsonl", rules: [{ when: { found: "*" }, emit: [{ op: "upsert", kind: "domain", key: { fqdn: "{{found}}" } }] }] },
    };

    const test = (await executeOperation("tool.test_manifest", { manifest, sampleOutput: '{"found":"x.cliente.example"}' }, ctx(agent))) as { items: number };
    expect(test.items).toBe(1);

    const proposal = (await executeOperation("tool.propose_manifest", { manifest, reason: "lo necesito para enumerar" }, ctx(agent))) as { approvalId: string };
    expect(runner.registry.get("fakeprobe")).toBeUndefined();
    await executeOperation("approval.approve", { approvalId: proposal.approvalId }, ctx(human));
    expect(runner.registry.get("fakeprobe")).toBeDefined();

    // Scope is checked from the manifest's target rules…
    await expect(
      executeOperation("tool.run", { tool: "fakeprobe", args: ["-d", "otro.example"] }, ctx(agent)),
    ).rejects.toMatchObject({ code: "OUT_OF_SCOPE" });

    // With targets, args are extra flags: the target stays in the command.
    const extra = (await executeOperation("tool.run", { tool: "fakeprobe", targets: ["www.cliente.example"], args: ["--verbose"], wait: 10 }, ctx(agent))) as {
      status: string;
    };
    expect(extra.status).toBe("finished");
    expect(eng.runs()[0]?.command).toContain("-d www.cliente.example --verbose");

    // …and the output is mapped into the graph without any code written for this tool.
    const result = (await executeOperation("tool.run", { tool: "fakeprobe", args: ["-d", "www.cliente.example"], wait: 10 }, ctx(agent))) as {
      status: string;
      summary: { ingested: { created: Record<string, number> } };
    };
    expect(result.status).toBe("finished");
    // The first run already created both domains; this one confirms them (new sightings).
    expect((result.summary.ingested as unknown as { updated: Record<string, number> }).updated).toEqual({ domain: 2 });
    expect(eng.findByKey("domain", "dev.cliente.example")).toBeDefined();
  });

  it("install proposals use the manifest recipe, never an arbitrary command", async () => {
    const proposal = (await executeOperation("tool.propose_install", { tool: "sqlmap", reason: "probar inyección" }, ctx(agent))) as { summary: string; approvalId: string };
    // The recipe follows this machine's package manager (apt here, pacman on Arch…).
    expect(proposal.summary).toMatch(/^Install sqlmap: (sudo apt install|sudo pacman -S --needed|sudo dnf install|brew install) sqlmap$/);
    const result = (await executeOperation("approval.approve", { approvalId: proposal.approvalId }, ctx(human))) as { status: string; command: string };
    expect(result.status).toBe("manual_install");
    expect(proposal.summary).toContain(result.command);
    await expect(executeOperation("tool.propose_install", { tool: "made-up", reason: "x" }, ctx(agent))).rejects.toMatchObject({ code: "NOT_FOUND" });
  });
});
