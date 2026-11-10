import { rulesOf } from "./rules.js";
import { listGaps } from "../../tools/capabilities.js";
import { defineOperation, OperationError } from "../registry.js";
import { Autonomy, RiskLevel, RoundMode } from "@penteos/schema";
import { z } from "zod";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { getPlan } from "../../plan.js";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// engagement
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "engagement.brief",
  title: "Engagement briefing",
  description:
    "Everything needed to get oriented in ONE call: engagement, scope, discovered assets with their scope status, open services, findings, observations, recent runs, installed tools and pending approvals. Call it first instead of many separate queries.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: async (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const info = e.info;
    const hosts = e.query({ kind: "host", limit: 200 });
    const services = e.query({ kind: "service", limit: 2000 });
    const hostById = new Map(hosts.map((h) => [h.id, h]));
    const tools = await ctx.runner(input.engagementId).registry.status();
    return {
      engagement: { name: info.name, client: info.clientName, mode: info.mode, roundMode: info.roundMode, status: info.status, maxRisk: info.maxRisk, dataPolicy: info.dataPolicy, autonomy: info.autonomy, stopWork: info.stopWork?.active ?? false },
      phases: (() => {
        const plan = getPlan(e);
        if (!plan.phases.length) return null;
        const cur = plan.phases.find((p) => p.id === plan.current);
        return {
          current: cur ? { id: cur.id, title: cur.title, goal: cur.goal, exploitationAllowed: cur.exploitation, plan: cur.plan ?? null } : null,
          all: plan.phases.map((p) => ({ id: p.id, title: p.title, status: p.status, ...(p.summary ? { summary: p.summary } : {}) })),
        };
      })(),
      // What the operator settled up front: test accounts (passwords by secret name), allowed, avoid.
      rules: (() => {
        const r = rulesOf(e);
        return r.accounts.length || r.allowed || r.avoid ? { accounts: r.accounts.map((a) => ({ ...a, ...(a.secret ? { use: `{{secret:${a.secret}}}` } : {}) })), allowed: r.allowed, avoid: r.avoid } : null;
      })(),
      // What the team remembers: attempts, decisions, hypotheses (latest first).
      memory: e
        .query({ kind: "memory", limit: 10_000 })
        .filter((m) => !m.attributes.invalidated)
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
        .slice(0, 25)
        .map((m) => ({ id: m.id, type: m.attributes.memoryType, content: m.attributes.content, trusted: m.attributes.trusted, at: m.createdAt })),
      // When each rule was added: an old denial may simply predate a scope change.
      scope: e.query({ kind: "scope_rule", limit: 1000 }).map((r) => ({ ...r.attributes, addedAt: r.createdAt })),
      counts: e.counts(),
      domains: e.query({ kind: "domain", limit: 200 }).map((d) => ({ fqdn: d.attributes.fqdn, inScope: !d.outOfScope })),
      hosts: hosts.map((h) => ({
        ip: h.attributes.ip,
        inScope: !h.outOfScope,
        hostnames: h.attributes.hostnames,
        open: services
          .filter((s) => s.attributes.hostId === h.id && s.attributes.state === "open")
          .map((s) => `${s.attributes.port}/${s.attributes.transport}${s.attributes.product ? ` ${s.attributes.product}${s.attributes.version ? ` ${s.attributes.version}` : ""}` : s.attributes.protocol ? ` ${s.attributes.protocol}` : ""}`),
      })),
      orphanServices: services.filter((s) => !hostById.has(String(s.attributes.hostId))).length,
      findings: e.query({ kind: "finding", limit: 100 }).map((f) => ({ id: f.id, title: f.attributes.title, severity: f.attributes.severity, status: f.attributes.status })),
      observations: e.query({ kind: "observation", limit: 100 }).map((o) => ({ title: o.attributes.title, triage: o.attributes.triage })),
      recentRuns: e.runs(10).map((r) => ({ at: r.startedAt, command: r.command, status: r.status, actor: r.actor.type, ...(r.policy.reason ? { reason: r.policy.reason } : {}), ...(r.summary?.ingested ? { ingested: (r.summary.ingested as { created?: unknown }).created } : {}) })),
      tools: {
        integrated: tools.filter((t) => t.installed && t.integrated).map((t) => t.name),
        installedNotIntegrated: tools.filter((t) => t.installed && !t.integrated).map((t) => t.name),
        missing: tools.filter((t) => !t.installed).map((t) => `${t.name}${t.install ? ` (installable: ${t.install.method === "catalog" ? "verified catalog, no root" : t.install.method})` : ""}${t.mismatch ? " (homonym binary found)" : ""}`),
      },
      // What missing tools left undone: resumed by Penteos itself once the tool appears.
      openGaps: listGaps(e)
        .filter((g) => g.status === "open")
        .map((g) => ({ id: g.id, capability: g.capability, severity: g.severity, tools: g.tools, targets: g.targets.slice(0, 10) })),
      pendingApprovals: ctx.runner(input.engagementId).listApprovals().map((a) => a.summary),
    };
  },
});

defineOperation({
  name: "engagement.list",
  title: "List engagements",
  description: "Lists the engagements in this workspace and which one is active.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({}),
  handler: (_input, ctx) => ({ active: ctx.defaultEngagementId ?? null, engagements: ctx.workspace.list() }),
});

defineOperation({
  name: "workspace.prefs",
  title: "Workspace preferences",
  description: "Whether the first-run assistant was completed and how the team works (solo or team).",
  kind: "read",
  actors: ["human"],
  input: z.object({}),
  handler: (_input, ctx) => {
    const { lastOpened: _l, languages: _g, ...prefs } = ctx.workspace.prefs();
    return { ...prefs, language: ctx.workspace.languageOf(ctx.caller.actor.id), languageSet: Boolean(ctx.workspace.prefs().languages?.[ctx.caller.actor.id]) };
  },
});

defineOperation({
  name: "operator.set_language",
  title: "Interface language",
  description: "The language this operator reads the interface in and talks to the Maestro in.",
  kind: "write",
  actors: ["human"],
  input: z.object({ language: z.enum(["es", "en"]) }),
  handler: (input, ctx) => {
    ctx.workspace.setLanguage(ctx.caller.actor.id, input.language);
    return { language: input.language };
  },
});

defineOperation({
  name: "workspace.set_prefs",
  title: "Change workspace preferences",
  description: "Marks the first-run assistant as done and records how the team works.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ onboarded: z.boolean().optional(), workStyle: z.enum(["solo", "team"]).optional(), projectsRoot: z.string().min(1).optional(), autonomy: Autonomy.optional() }),
  handler: (input, ctx) => {
    const { lastOpened: _l, ...prefs } = ctx.workspace.setPrefs({
      ...(input.onboarded !== undefined ? { onboarded: input.onboarded } : {}),
      ...(input.workStyle ? { workStyle: input.workStyle } : {}),
      ...(input.projectsRoot ? { projectsRoot: input.projectsRoot } : {}),
      ...(input.autonomy ? { autonomy: input.autonomy } : {}),
    });
    return prefs;
  },
});

defineOperation({
  name: "engagement.update",
  title: "Change engagement",
  description: "Renames the engagement or changes its target type (web, infra), round mode (pentest, retest, continuous), risk ceiling or autonomy (copilot, maestro, maestro_auto).",
  kind: "admin",
  actors: ["human"],
  input: z.object({
    engagementId,
    name: z.string().min(1).optional(),
    mode: z.enum(["web", "infra", "custom"]).optional(),
    roundMode: RoundMode.optional(),
    maxRisk: RiskLevel.optional(),
    autonomy: Autonomy.optional().describe("copilot (suggests, operator approves each action), maestro (runs, interrupts on decisions), maestro_auto (autopilot: batches decisions)"),
    language: z.enum(["es", "en"]).optional().describe("Language of the deliverable"),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    if (input.autonomy && input.autonomy !== "copilot" && e.info.dataPolicy === "no_ai") throw new OperationError("VALIDATION_ERROR", "the project data policy does not allow AI");
    const next = {
      ...e.info,
      ...(input.name ? { name: input.name } : {}),
      ...(input.mode ? { mode: input.mode } : {}),
      ...(input.roundMode ? { roundMode: input.roundMode } : {}),
      ...(input.maxRisk ? { maxRisk: input.maxRisk } : {}),
      ...(input.autonomy ? { autonomy: input.autonomy } : {}),
      ...(input.language ? { language: input.language } : {}),
    };
    e.setInfo(next, ctx.caller.actor);
    ctx.workspace.syncIndex(next);
    return next;
  },
});

defineOperation({
  name: "engagement.create",
  title: "Create engagement",
  description: "Creates a new engagement for a client.",
  kind: "admin",
  actors: ["human"],
  input: z.object({
    clientName: z.string().min(1),
    name: z.string().min(1),
    mode: z.enum(["web", "infra", "custom"]),
    roundMode: RoundMode.optional(),
    maxRisk: RiskLevel.optional(),
    autonomy: Autonomy.optional(),
    language: z.enum(["es", "en"]).optional().describe("Language of the deliverable"),
    dir: z.string().min(1).optional().describe("Parent folder for this project's folder; defaults to the projects root"),
    plugins: z.array(z.string().max(80)).max(100).optional().describe("Installed plugins to enable in this project"),
  }),
  handler: (input, ctx) => {
    // Only plugins that are installed and running can be enabled (a typo would silently do nothing).
    for (const id of input.plugins ?? []) {
      if (ctx.plugins?.get(id)?.status !== "active") throw new OperationError("PLUGIN_UNAVAILABLE", `the plugin ${id} is not active`);
    }
    return ctx.workspace.create(input, ctx.caller.actor).info;
  },
});

defineOperation({
  name: "engagement.get",
  title: "Engagement overview",
  description: "Returns the engagement's metadata, entity counts and scope rules. Start here to understand what you are working on.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    return { ...e.info, counts: e.counts(), scope: e.scopeRules() };
  },
});

for (const stop of [true, false]) {
  defineOperation({
    name: stop ? "engagement.stop_work" : "engagement.resume_work",
    title: stop ? "Stop work" : "Resume work",
    description: stop
      ? "Stops every running tool and blocks all target operations, for humans and agents, until work is resumed."
      : "Lifts a stop-work order.",
    kind: "admin",
    actors: ["human"],
    input: z.object({ engagementId, reason: stop ? z.string().min(1) : z.string().optional() }),
    handler: (input, ctx) => {
      const e = ctx.engagement(input.engagementId);
      const info = e.info;
      const next = { ...info };
      if (stop) next.stopWork = { active: true, by: ctx.caller.actor, at: new Date().toISOString(), reason: input.reason ?? "" };
      else delete next.stopWork;
      e.setInfo(next, ctx.caller.actor, stop ? "engagement.stop_work" : "engagement.resume_work");
      const cancelled = stop ? ctx.runner(input.engagementId).cancelAll() : 0;
      return { stopWork: stop, cancelledRuns: cancelled };
    },
  });
}
