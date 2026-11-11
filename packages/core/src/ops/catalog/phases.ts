import { WSTG, wstgTitle } from "../../wstg.js";
import { undecidedSurface } from "../../surface.js";
import type { OperationContext } from "../registry.js";
import { gapLine, isCritical, listGaps } from "../../tools/capabilities.js";
import { defineOperation, OperationError } from "../registry.js";
import { z } from "zod";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { getPlan, localizePlan, setPhase, setPhasePlan, setPhaseSummary } from "../../plan.js";
import { join } from "node:path";
import { engagementId } from "./shared.js";
import { canonicalOrigin } from "../../tools/runner.js";
import { findingsToDeepen } from "../../impact.js";

// ---------------------------------------------------------------------------------------------
// Phases of the work

/** Phases only a person moves to: writing up and closing an engagement. */
const FINAL_PHASES = new Set(["reporting", "closing"]);

defineOperation({
  name: "plan.get",
  title: "Phases and plan",
  description: "The phases of this engagement, which one is current, the plan written for each and what came out of the finished ones. Exploitation by agents is only possible in phases that allow it.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  // A person reads the phase names in their interface language; agents, in the deliverable's.
  handler: (input, ctx) => {
    const plan = getPlan(ctx.engagement(input.engagementId));
    return ctx.caller.actor.type === "human" ? localizePlan(plan, ctx.workspace.languageOf(ctx.caller.actor.id)) : plan;
  },
});

defineOperation({
  name: "plan.set_phase_plan",
  title: "Write the plan of a phase",
  description: "Writes what will be done in a phase (short markdown list: steps, tools, what each one answers). Do it when a phase starts, before acting.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, phase: z.string(), plan: z.string().min(1) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const plan = setPhasePlan(e, input.phase, input.plan, ctx.caller.actor);
    // The phase is starting: the tools it usually needs, offered once (the first phase has no pass).
    if (plan.current === input.phase) void ctx.runner(input.engagementId).proposePhaseKit(input.phase, ctx.caller.actor).catch(() => undefined);
    return plan;
  },
});

defineOperation({
  name: "plan.set_phase_summary",
  title: "Summarize a phase",
  description: "Writes what came out of a phase: what was done, what was found, what is left.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, phase: z.string(), summary: z.string().min(1) }),
  handler: (input, ctx) => setPhaseSummary(ctx.engagement(input.engagementId), input.phase, input.summary, ctx.caller.actor),
});

defineOperation({
  name: "phase.request",
  title: "Ask to move to another phase",
  description:
    "Closes the current phase with a summary (what was done, found and left) and asks the operator to move to the next one. The operator sees it as a card and decides; you are told the result. Required before exploitation.",
  kind: "write",
  actors: ["agent"],
  input: z.object({ engagementId, to: z.string(), summary: z.string().min(1) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const plan = getPlan(e);
    const phase = plan.phases.find((p) => p.id === input.to);
    if (!phase) throw new OperationError("VALIDATION_ERROR", `unknown phase "${input.to}"; phases: ${plan.phases.map((p) => p.id).join(", ")}`);
    // Writing up is the operator's call, never the agent's: the agent ends a round with where things
    // stand and the paths left (plan_propose_paths), and the operator moves to reporting when they want.
    if (FINAL_PHASES.has(phase.id)) {
      throw new OperationError(
        "PERMISSION_DENIED",
        `moving to "${phase.title}" is the operator's decision, not yours. Do not ask for it and do not mention it: close this round with plan_propose_paths (where things stand and what is worth exploring next) and wait. When the operator wants the deliverable they move the phase themselves.`,
      );
    }
    // Already there: don't open another pass for a transition that already happened (this was the
    // observed back-and-forth: re-requesting a phase the operator had already granted).
    if (plan.current === input.to) {
      return { status: "already_in_phase", phase: input.to, note: `You are already in "${phase.title}". There is nothing to request: do the work of this phase, and close the round with plan_propose_paths when you are done.` };
    }
    const runner = ctx.runner(input.engagementId);
    // A pass to this phase is already waiting: hand back that one instead of stacking a duplicate.
    const pending = runner.listApprovals().find((a) => a.request.kind === "phase" && a.request.to === input.to);
    if (pending) {
      return { status: "already_pending", approvalId: pending.id, note: `A pass to "${phase.title}" is already waiting for the operator; don't ask again. Keep working or wait for their decision.` };
    }
    // Gaps of this phase (what a missing tool kept from being done). A critical one, the phase's
    // central work with no source at all, stops the request: the operator decides there, not here.
    const lang0 = e.info.language ?? "en";
    const phaseGaps = listGaps(e).filter((g) => g.status === "open" && (!g.phase || g.phase === plan.current));
    const critical = phaseGaps.filter(isCritical);
    if (critical.length) {
      throw new OperationError(
        "VALIDATION_ERROR",
        `This phase cannot close yet: its central work has no source at all - ${critical.map((g) => `gap ${g.id}: ${gapLine(g, "en")}`).join("; ")}. The install was proposed to the operator; keep doing whatever else you can, and when nothing is left, tell the operator in one line what is missing and wait. Do not ask for the phase again until the gap is resolved or the operator moves on.`,
      );
    }
    const blocked = closingBlockers(e);
    if (blocked) throw new OperationError("VALIDATION_ERROR", blocked);
    if (plan.current) setPhaseSummary(e, plan.current, input.summary, ctx.caller.actor);
    // Leaving the analysis with categories nobody looked at is a decision the operator makes knowingly.
    const warnings: string[] = [];
    const lang = e.info.language ?? "en";
    if (plan.current === "analysis") {
      for (const app of e.query({ kind: "webapp", limit: 500 }).filter((a) => !a.outOfScope)) {
        const cov = (app.attributes.coverage ?? {}) as Record<string, { status?: string }>;
        const missing = WSTG.filter((c) => !cov[c.id] || cov[c.id]!.status === "untested" || cov[c.id]!.status === "in_progress").map((c) => wstgTitle(c, lang).toLowerCase());
        const origin = String(app.attributes.origin).replace(/^(https:\/\/[^/]+):443$|^(http:\/\/[^/]+):80$/, "$1$2");
        const list = `${missing.slice(0, 5).join(", ")}${missing.length > 5 ? "…" : ""}`;
        // Shown on the phase approval, next to the project's own phase names: in the project language.
        if (missing.length) warnings.push(lang === "en" ? `${origin}: ${missing.length} of ${WSTG.length} categories not covered (${list})` : `${origin}: ${missing.length} de ${WSTG.length} categorías sin cubrir (${list})`);
      }
    }
    if (plan.current === "analysis") warnings.push(...depthGaps(e, lang));
    // Serious findings whose impact nobody measured: the report would say "detected", not "how bad".
    warnings.push(...impactGaps(e, lang));
    // What missing tools left undone (or done with Penteos's own, lesser method): on the card.
    for (const g of phaseGaps) warnings.push(lang0 === "en" ? `Tool gap: ${gapLine(g, "en")}` : `Hueco de herramientas: ${gapLine(g, "es")}`);
    // High-signal observations nobody promoted or dismissed - the verifier never saw them.
    const loose = untriagedObservations(e);
    if (loose.length) warnings.push(lang === "en" ? `${loose.length} high-signal observation(s) neither promoted nor dismissed (e.g. «${loose[0]!.title}»)` : `${loose.length} observación(es) de señal alta sin promover ni descartar (p. ej. «${loose[0]!.title}»)`);
    const approval = runner.proposePhase(input.to, phase.title, input.summary, ctx.caller.actor, warnings);
    return { status: "pending_approval", approvalId: approval.id, summary: approval.summary, ...(warnings.length ? { note: `The operator sees these gaps on the card: ${warnings.join(" | ")}. If you can still close them without credentials, withdraw this request and do it first.` } : {}) };
  },
});

defineOperation({
  name: "phase.set",
  title: "Change phase",
  description: "Moves the engagement to a phase (human decision).",
  kind: "target",
  actors: ["human"],
  input: z.object({ engagementId, phase: z.string(), summary: z.string().optional() }),
  handler: (input, ctx) => {
    try {
      const plan = setPhase(ctx.engagement(input.engagementId), input.phase, ctx.caller.actor, input.summary);
      void ctx.runner(input.engagementId).proposePhaseKit(input.phase, ctx.caller.actor).catch(() => undefined);
      return plan;
    } catch (e) {
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
  },
});

const IMPACT_LABEL: Record<"es" | "en", Record<string, string>> = {
  es: { reach: "alcance", exposed: "qué permite lo expuesto", chain: "encadenamiento" },
  en: { reach: "reach", exposed: "what the exposed data allows", chain: "chaining" },
};

/** High-signal observations nobody acted on: not promoted to a finding and not dismissed. */
/** Phases where the analysis is underway or done: from then on every WSTG category needs a state. */
const ANALYSIS_OR_LATER = new Set(["analysis", "exploitation", "verification"]);

/**
 * What keeps a round (or a phase) from closing, as one message for the agent, or undefined: surface
 * found outside the scope that nobody decided on, and - once the analysis is underway - WSTG
 * categories of in-scope applications that nobody tested or marked partial / not applicable with a
 * reason. "I did not get to it" is not a reason; "no test account" is.
 */
export function closingBlockers(e: ReturnType<OperationContext["engagement"]>): string | undefined {
  const parts: string[] = [];
  const undecided = undecidedSurface(e);
  if (undecided.length) {
    parts.push(
      `${undecided.length} host(s) of the client's domains were found outside the scope and nobody decided on them: ${undecided
        .slice(0, 10)
        .map((s) => `${s.host}${s.title ? ` («${s.title}»)` : ""}`)
        .join(", ")}${undecided.length > 10 ? "…" : ""}. Look at what each one is, then surface_decide: propose including the ones worth testing (say why: an exposed tool, a QA environment, plain HTTP, a known-vulnerable version) and set aside the rest with the reason.`,
    );
  }
  const plan = getPlan(e);
  if (plan.current && ANALYSIS_OR_LATER.has(plan.current)) {
    const apps: string[] = [];
    for (const app of e.query({ kind: "webapp", limit: 500 }).filter((a) => !a.outOfScope)) {
      const cov = (app.attributes.coverage ?? {}) as Record<string, { status?: string }>;
      const missing = WSTG.filter((c) => !cov[c.id] || cov[c.id]!.status === "untested" || cov[c.id]!.status === "in_progress").map((c) => c.id);
      if (missing.length) apps.push(`${String(app.attributes.origin).replace(/:(443|80)$/, "")} (${app.id}): ${missing.join(", ")}`);
    }
    if (apps.length) {
      parts.push(
        `WSTG categories still untested: ${apps.slice(0, 8).join("; ")}${apps.length > 8 ? "…" : ""}. Test them, or record each with webapp_set_coverage (categories: [...]) as partial or n/a with the reason in the note (e.g. "no test account", "no file upload on this app").`,
      );
    }
  }
  return parts.length ? `This round cannot close yet. ${parts.join(" ")}` : undefined;
}

export function untriagedObservations(e: ReturnType<OperationContext["engagement"]>): Array<{ id: string; title: string; severity: string }> {
  return e
    .query({ kind: "observation", limit: 5000 })
    // Leads (a 5xx, an origin the CDN cannot reach) count whatever their severity: they are the
    // places a round must look at before it ends, not noise.
    .filter((o) => (String(o.attributes.triage ?? "new") === "new") && !o.attributes.findingId && (["high", "critical"].includes(String(o.attributes.severityHint ?? "")) || String(o.attributes.sourceRule ?? "").startsWith("lead:")))
    .map((o) => ({ id: o.id, title: String(o.attributes.title), severity: String(o.attributes.severityHint) }));
}

/** Findings with impact questions still open, one line each (in the project language). */
export function impactGaps(e: ReturnType<OperationContext["engagement"]>, lang: "es" | "en"): string[] {
  return findingsToDeepen(e)
    .slice(0, 8)
    .map((f) => `${lang === "en" ? "Impact not measured" : "Impacto sin medir"} · «${f.title}»: ${f.open.map((k) => IMPACT_LABEL[lang][k]).join(", ")}`);
}

/**
 * Tests that need no credentials and were not done, per in-scope application: its JavaScript never
 * harvested, endpoints known but never requested, no sweep of the auth boundary, login without a
 * rate-limit test. Shown on the card that closes the analysis, so leaving them is a decision.
 */
function depthGaps(e: ReturnType<OperationContext["engagement"]>, lang: "es" | "en"): string[] {
  const runs = e.runs(100000).filter((r) => r.status === "finished");
  // Same origin whatever the port notation ("https://x" in a run, "https://x:443" in the graph).
  const ranOn = (tool: string, origin: string) => runs.some((r) => r.tool === tool && r.targets.some((t) => canonicalOrigin(t) === canonicalOrigin(origin)));
  const endpoints = e.query({ kind: "endpoint", limit: 50_000 });
  const out: string[] = [];
  for (const app of e.query({ kind: "webapp", limit: 500 }).filter((a) => !a.outOfScope)) {
    const origin = String(app.attributes.origin);
    const shown = origin.replace(/^(https:\/\/[^/]+):443$|^(http:\/\/[^/]+):80$/, "$1$2");
    const mine = endpoints.filter((ep) => ep.attributes.webappId === app.id);
    const gaps: string[] = [];
    if (!ranOn("webjs", origin)) gaps.push(lang === "en" ? "JavaScript not harvested" : "JavaScript sin analizar");
    const never = mine.filter((ep) => !((ep.attributes.statusesSeen as number[] | undefined) ?? []).length).length;
    if (never > 0) gaps.push(lang === "en" ? `${never} known endpoint(s) never requested` : `${never} endpoint(s) conocidos sin pedir nunca`);
    if (mine.length >= 5 && !ranOn("apiprobe", origin)) gaps.push(lang === "en" ? "auth boundary not swept" : "frontera de autenticación sin barrer");
    const login = mine.some((ep) => /login|signin|sign-in|auth|token|password|forgot|reset|otp|2fa|mfa/i.test(String(ep.attributes.pathTemplate)));
    if (login && !ranOn("ratelimit", origin)) gaps.push(lang === "en" ? "login without a rate-limit test" : "login sin prueba de límite de intentos");
    if (gaps.length) out.push(`${shown}: ${gaps.join(", ")}`);
  }
  return out;
}
