import { describe, expect, it } from "vitest";
import { type ActorPolicy, evaluateScope, type ScopeRule } from "../src/index.js";

const human: ActorPolicy = { type: "human" };
const autonomousAgent: ActorPolicy = { type: "agent", autonomy: "autonomous", maxRisk: "active" };

const engagement = { maxRisk: "intrusive" as const };

const rules: ScopeRule[] = [
  { id: "inc-wild", effect: "include", target: { type: "wildcard", value: "*.cliente.example" } },
  { id: "inc-apex", effect: "include", target: { type: "domain", value: "cliente.example" } },
  { id: "inc-net", effect: "include", target: { type: "cidr", value: "203.0.113.0/24" } },
  { id: "inc-lan", effect: "include", target: { type: "cidr", value: "10.0.0.0/24" }, networkContext: "corp-lan" },
  { id: "inc-api", effect: "include", target: { type: "url", value: "https://partner.example.org/api/" } },
  {
    id: "exc-erp",
    effect: "exclude",
    target: { type: "domain", value: "erp.cliente.example" },
    reason: "producción crítica",
  },
  { id: "exc-db", effect: "exclude", target: { type: "ip", value: "203.0.113.50" } },
  { id: "inc-legacy", effect: "include", target: { type: "domain", value: "legacy.otro.example" }, maxRisk: "passive" },
];

function check(target: string, extra: Partial<Parameters<typeof evaluateScope>[2]> = {}) {
  return evaluateScope(engagement, rules, { target, risk: "active", actor: human, ...extra });
}

describe("inclusions and default deny", () => {
  it("allows subdomains under a wildcard", () => {
    expect(check("app.cliente.example")).toMatchObject({ decision: "allow", ruleId: "inc-wild" });
  });

  it("does not let a wildcard cover the apex; the apex needs its own rule", () => {
    expect(check("cliente.example")).toMatchObject({ decision: "allow", ruleId: "inc-apex" });
    const onlyWildcard = rules.filter((r) => r.id !== "inc-apex");
    expect(evaluateScope(engagement, onlyWildcard, { target: "cliente.example", risk: "active", actor: human })).toMatchObject({
      decision: "deny",
      code: "OUT_OF_SCOPE",
    });
  });

  it("denies anything not explicitly included", () => {
    expect(check("admin.otrodominio.example")).toMatchObject({ decision: "deny", code: "OUT_OF_SCOPE" });
    expect(check("198.51.100.7")).toMatchObject({ decision: "deny", code: "OUT_OF_SCOPE" });
  });

  it("requires an inclusion to cover the whole CIDR", () => {
    expect(check("203.0.113.0/25")).toMatchObject({ decision: "deny", code: "OUT_OF_SCOPE" }); // overlaps exc-db
    expect(check("203.0.113.128/25")).toMatchObject({ decision: "allow", ruleId: "inc-net" });
    expect(check("203.0.112.0/23")).toMatchObject({ decision: "deny", code: "OUT_OF_SCOPE" }); // wider than the rule
  });

  it("restricts URL rules to their origin and path prefix", () => {
    expect(check("https://partner.example.org/api/v1/users")).toMatchObject({ decision: "allow", ruleId: "inc-api" });
    expect(check("https://partner.example.org/admin")).toMatchObject({ decision: "deny", code: "OUT_OF_SCOPE" });
    expect(check("partner.example.org")).toMatchObject({ decision: "deny", code: "OUT_OF_SCOPE" });
  });
});

describe("exclusions", () => {
  it("always win over inclusions", () => {
    expect(check("erp.cliente.example")).toMatchObject({ decision: "deny", code: "OUT_OF_SCOPE", ruleId: "exc-erp" });
    expect(check("https://erp.cliente.example/login")).toMatchObject({ decision: "deny", ruleId: "exc-erp" });
  });

  it("apply when a range merely overlaps them", () => {
    expect(check("203.0.113.0/24")).toMatchObject({ decision: "deny", ruleId: "exc-db" });
    expect(check("203.0.113.50:5432")).toMatchObject({ decision: "deny", ruleId: "exc-db" });
  });
});

describe("network contexts", () => {
  it("only applies context-specific rules inside that context", () => {
    expect(check("10.0.0.5")).toMatchObject({ decision: "deny", code: "OUT_OF_SCOPE" });
    expect(check("10.0.0.5", { networkContext: "corp-lan" })).toMatchObject({ decision: "allow", ruleId: "inc-lan" });
  });
});

describe("ports", () => {
  const portRules: ScopeRule[] = [
    { id: "web-only", effect: "include", target: { type: "ip", value: "192.0.2.10" }, ports: "80,443,8000-8100" },
    { id: "no-ssh", effect: "exclude", target: { type: "ip", value: "192.0.2.20" }, ports: "22" },
    { id: "box", effect: "include", target: { type: "ip", value: "192.0.2.20" } },
  ];
  const run = (target: string) => evaluateScope(engagement, portRules, { target, risk: "active", actor: human });

  it("covers only the listed ports", () => {
    expect(run("192.0.2.10:443")).toMatchObject({ decision: "allow" });
    expect(run("192.0.2.10:8050")).toMatchObject({ decision: "allow" });
    expect(run("192.0.2.10:22")).toMatchObject({ decision: "deny", code: "OUT_OF_SCOPE" });
  });

  it("treats an unknown port as touching every port", () => {
    expect(run("192.0.2.10")).toMatchObject({ decision: "deny", code: "OUT_OF_SCOPE" });
    expect(run("192.0.2.20")).toMatchObject({ decision: "deny", ruleId: "no-ssh" });
    expect(run("192.0.2.20:80")).toMatchObject({ decision: "allow", ruleId: "box" });
  });
});

describe("risk", () => {
  it("enforces the engagement ceiling", () => {
    expect(check("app.cliente.example", { risk: "exploitation" })).toMatchObject({ decision: "deny", code: "RISK_EXCEEDED" });
  });

  it("enforces per-rule ceilings", () => {
    expect(check("legacy.otro.example", { risk: "passive" })).toMatchObject({ decision: "allow" });
    expect(check("legacy.otro.example", { risk: "active" })).toMatchObject({ decision: "deny", code: "RISK_EXCEEDED" });
  });
});

describe("agents", () => {
  it("lets an autonomous agent act within its own ceiling", () => {
    expect(check("app.cliente.example", { actor: autonomousAgent })).toMatchObject({ decision: "allow" });
  });

  it("asks a human when the agent goes beyond its own ceiling", () => {
    expect(check("app.cliente.example", { actor: autonomousAgent, risk: "intrusive" })).toMatchObject({
      decision: "ask",
      ruleId: "inc-wild",
    });
  });

  it("always asks for agents that require approval", () => {
    const agent: ActorPolicy = { type: "agent", autonomy: "with_approval", maxRisk: "exploitation" };
    expect(check("app.cliente.example", { actor: agent, risk: "passive" })).toMatchObject({ decision: "ask" });
  });

  it("never turns an out-of-scope target into a question", () => {
    expect(check("admin.otrodominio.example", { actor: autonomousAgent })).toMatchObject({ decision: "deny" });
  });
});

describe("stop-work and dates", () => {
  it("stop-work denies everything", () => {
    const stopped = {
      ...engagement,
      stopWork: { active: true, by: { type: "system" as const, id: "test" }, at: "2026-10-13T10:00:00Z", reason: "white cell" },
    };
    expect(evaluateScope(stopped, rules, { target: "app.cliente.example", risk: "passive", actor: human })).toMatchObject({
      decision: "deny",
      code: "STOP_WORK_ACTIVE",
    });
  });

  it("denies outside the engagement dates", () => {
    const dated = { ...engagement, startsAt: "2026-11-01T00:00:00Z", endsAt: "2026-11-30T00:00:00Z" };
    const query = { target: "app.cliente.example", risk: "passive" as const, actor: human };
    expect(evaluateScope(dated, rules, { ...query, now: new Date("2026-10-13T12:00:00Z") })).toMatchObject({
      code: "OUTSIDE_WINDOW",
    });
    expect(evaluateScope(dated, rules, { ...query, now: new Date("2026-11-10T12:00:00Z") })).toMatchObject({
      decision: "allow",
    });
  });
});

describe("time windows", () => {
  const windowed: ScopeRule[] = [
    {
      id: "nights",
      effect: "include",
      target: { type: "domain", value: "pos.cliente.example" },
      // Mon-Fri 22:00-06:00 Buenos Aires time
      windows: [{ days: [1, 2, 3, 4, 5], start: "22:00", end: "06:00", timeZone: "America/Argentina/Buenos_Aires" }],
    },
  ];
  const at = (iso: string) =>
    evaluateScope(engagement, windowed, { target: "pos.cliente.example", risk: "active", actor: human, now: new Date(iso) });

  it("allows inside an overnight window, including after midnight", () => {
    expect(at("2026-10-14T02:00:00Z")).toMatchObject({ decision: "allow" }); // Tue 23:00 ART
    expect(at("2026-10-14T07:30:00Z")).toMatchObject({ decision: "allow" }); // Wed 04:30 ART
  });

  it("denies outside the window", () => {
    expect(at("2026-10-14T15:00:00Z")).toMatchObject({ decision: "deny", code: "OUTSIDE_WINDOW" }); // Wed 12:00 ART
    expect(at("2026-10-18T07:00:00Z")).toMatchObject({ decision: "deny", code: "OUTSIDE_WINDOW" }); // Sun 04:00 ART
  });
});

describe("warnings", () => {
  it("asks when an in-scope name resolves to an excluded IP", () => {
    expect(check("db.cliente.example", { resolvedIps: ["203.0.113.50"] })).toMatchObject({
      decision: "ask",
      warnings: [expect.stringContaining("203.0.113.50")],
    });
  });
});

describe("invalid input", () => {
  it("denies targets that cannot be parsed", () => {
    expect(check("not a target!")).toMatchObject({ decision: "deny", code: "INVALID_TARGET" });
    expect(check("*.cliente.example")).toMatchObject({ decision: "deny", code: "INVALID_TARGET" });
  });
});
