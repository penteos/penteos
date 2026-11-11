import type { RunOutcome } from "../../tools/runner.js";
import { OperationError, type OperationContext } from "../registry.js";
import { z } from "zod";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { join } from "node:path";

/** Helpers every group of operations shares. */

/** The v0 operation catalog. */

export const engagementId = z.string().optional().describe("Engagement id. Defaults to the active engagement.");

/** Target-controlled content is wrapped for agents. */
export function untrusted(ctx: OperationContext, content: string): string | { untrusted: true; content: string } {
  // Agents never see secret values, even when a target echoes them back (Set-Cookie, a form…).
  return ctx.caller.actor.type === "agent" ? { untrusted: true, content: ctx.engagement().redact(content) } : content;
}

export function outcome(result: RunOutcome | undefined, ctx?: OperationContext): unknown {
  if (!result) return { status: "rejected" };
  if (result.status === "http") {
    const r = result.response;
    // Whole up to a generous size: what reaches the model is fitted by structure later (privacy/fit.ts).
    const body = r ? (r.body.length > MAX_BODY ? `${r.body.slice(0, MAX_BODY)}\n[… ${r.body.length - MAX_BODY} more characters: read them with raw_get]` : r.body) : "";
    return {
      status: result.error ? "failed" : "done",
      runId: result.run.id,
      ...(result.rawId ? { rawId: result.rawId } : {}),
      ...(result.error ? { error: result.error } : {}),
      ...(r
        ? {
            response: {
              status: r.status,
              statusText: r.statusText,
              timeMs: r.timeMs,
              size: r.size,
              headers: ctx ? untrusted(ctx, r.headers.map(([k, v]) => `${k}: ${v}`).join("\n")) : r.headers,
              body: ctx ? untrusted(ctx, body) : body,
            },
          }
        : {}),
    };
  }
  if (result.status === "scope_added" || result.status === "rules_set" || result.status === "manifest_saved" || result.status === "manual_install" || result.status === "phase_changed" || result.status === "findings_approved") return result;
  if (result.status === "denied") {
    throw new OperationError(result.code as never, result.reason, { runId: result.run.id });
  }
  if (result.status === "pending_approval") {
    return {
      status: "pending_approval",
      approvalId: result.approval.id,
      reason: result.approval.reason,
      summary: result.approval.summary,
      ...(result.duplicate ? { note: "You already asked for exactly this and it is still waiting for the operator. Do not ask again; continue with something else." } : {}),
    };
  }
  if (result.status === "ws") {
    if (result.error) return { status: "failed", error: result.error, entryId: result.entryId ?? null, httpStatus: result.httpStatus ?? null };
    return { status: "open", sessionId: result.sessionId, entryId: result.entryId };
  }
  if (result.status === "harvest") {
    const h = result.harvest;
    return {
      status: result.error ? "failed" : "done",
      runId: result.run.id,
      ...(result.rawId ? { rawId: result.rawId } : {}),
      ...(result.error ? { error: result.error } : {}),
      ...(h
        ? {
            endpoints: h.endpoints.map((e) => (e.origin ? `${e.origin}${e.path}` : e.path)).slice(0, 300),
            hosts: h.hosts,
            routes: h.routes.slice(0, 300),
            secrets: h.secrets.map((x) => x.kind),
            sourceMaps: h.sourceMaps,
            ...(result.apiBases?.length ? { apiBases: result.apiBases } : {}),
            note: [
              "Endpoints and webapps for in-scope origins were added to the graph; out-of-scope hosts, secrets and source maps are observations. Test the endpoints next; propose scope rules for in-scope-worthy hosts.",
              ...(() => {
                const apis = (result.apiBases ?? []).filter((b) => b.origin !== result.pageOrigin);
                if (!apis.length || !h.endpoints.length) return [];
                const inScope = apis.filter((b) => b.inScope);
                const out = apis.filter((b) => !b.inScope);
                return [
                  `The code calls an API on another host (${apis.map((b) => b.origin).join(", ")}) with relative paths.`,
                  inScope.length
                    ? `Sweep the app's calls there without credentials in one call: web_probe_endpoints with origin ${inScope[0]!.origin} and fromOrigin ${result.pageOrigin} (no basePath: Penteos measures which base path the calls live under, then requests them all).`
                    : `Propose ${out.map((b) => new URL(b.origin).hostname).join(", ")} with scope_propose_rule; once included, sweep the app's calls there: web_probe_endpoints with origin ${out[0]!.origin} and fromOrigin ${result.pageOrigin} (no basePath: Penteos finds it by measuring).`,
                ];
              })(),
            ].join(" "),
          }
        : {}),
    };
  }
  if (result.status === "versions") {
    if (result.error || !result.found) return { status: "failed", runId: result.run.id, error: result.error ?? "no result" };
    const found = result.found;
    return {
      status: "done",
      runId: result.run.id,
      found: found.map((f) => ({ product: f.product, version: f.version, source: f.source, confidence: Math.round(f.confidence * 100) / 100, ...(f.ecosystem ? { ecosystem: f.ecosystem } : {}) })),
      ...(result.rawId ? { rawId: result.rawId } : {}),
      note: found.length
        ? `${found.length} exact version(s) from reliable sources, now technologies. Run vuln_lookup on them. Prefer these over an asset's ?ver= (often a cache-buster) or a guess.`
        : "No version revealed by the headers, the generator meta, WordPress files or exposed manifests. If you read a version elsewhere, register it with tech_add; a ?ver= on an asset is not reliable.",
    };
  }
  if (result.status === "enumeration") {
    if (result.error || !result.result) return { status: "failed", runId: result.run.id, error: result.error ?? "no result" };
    const r = result.result;
    return {
      status: "done",
      runId: result.run.id,
      ...r,
      rawId: result.rawId,
      ...(result.sampleRawId ? { sampleRawId: result.sampleRawId } : {}),
      note:
        r.estimate === 0
          ? `No identifier answered with a record (a missing one answers ${r.missing.status}). If the ids are not integers, pass values (slugs or codes seen in the app).`
          : `${r.exact ? "Exact count" : "Estimate"}: ${r.estimate} record(s)${r.highest ? `, ids up to ${r.highest}` : ""}. Make it evidence (evidence_from_raw with rawId for the log${result.sampleRawId ? ", sampleRawId for one record" : ""}) and answer the reach question (finding_answer_impact key reach). Do not read the records one by one: the measure is the proof.`,
    };
  }
  if (result.status === "serveractions") {
    const results = result.results ?? [];
    const by = (v: string) => results.filter((r) => r.verdict === v);
    return {
      status: result.error ? "failed" : "done",
      runId: result.run.id,
      ran: by("ran").map((r) => r.name ?? r.id),
      protected: by("protected").length,
      failed: by("failed").map((r) => r.name ?? r.id),
      missing: by("missing").length,
      ...(result.rawId ? { rawId: result.rawId } : {}),
      ...(result.error ? { error: result.error } : {}),
      note: by("ran").length
        ? "Each action that ran is an observation: read its answer (rawId) and what it does; promote the ones that read or change what this caller should not reach. Failed ones are leads: vary the arguments."
        : "None ran for this caller.",
    };
  }
  if (result.status === "ratelimit") {
    const results = result.results ?? [];
    const open = results.filter((r) => r.verdict === "no_defence");
    const measured = results.filter((r) => r.verdict === "no_defence" || r.verdict === "defended");
    return {
      status: result.error ? "failed" : "done",
      runId: result.run.id,
      verdict: result.error ? "failed" : !measured.length ? "not_measured" : open.length === 0 ? "defended" : open.length === measured.length && measured.length === results.length ? "no_defence" : "mixed",
      // The first endpoint's figures stay at the top for single-request calls.
      attempts: result.attempts,
      defence: result.defence ?? null,
      results,
      ...(result.rawId ? { rawId: result.rawId } : {}),
      ...(result.error ? { error: result.error } : {}),
      note: result.error
        ? "The probe failed before finishing; read the error."
        : `This result is conclusive: do not repeat it with run_exec, curl loops or another probe. ${
            open.length
              ? `No defence on ${open.map((r) => r.request).join(", ")}: an observation was recorded on each; with rawId as evidence, propose a finding if they guard credentials or codes (template no-login-rate-limit).`
              : measured.length
                ? "Every endpoint that exists pushed back."
                : "Nothing was measured."
          }${(() => {
            const missing = results.filter((r) => r.verdict === "missing").map((r) => r.request);
            const failing = results.filter((r) => r.verdict === "inconclusive").map((r) => r.request);
            return `${missing.length ? ` These routes do not exist (no limit to measure, not a finding): ${missing.join(", ")}.` : ""}${failing.length ? ` These only answered server errors (inconclusive, not a finding): ${failing.join(", ")}.` : ""}`;
          })()}`,
    };
  }
  if (result.status === "browser") {
    if (result.error || !result.result) return { status: "failed", runId: result.run.id, error: result.error ?? "no result" };
    const r = result.result;
    const blocked = r.requests.filter((q) => q.status === 403).length;
    return {
      status: "done",
      runId: result.run.id,
      page: r.page,
      requests: r.requests.slice(0, 80),
      ...(r.dialogs.length ? { dialogs: r.dialogs } : {}),
      ...(r.console.length ? { console: r.console } : {}),
      rawId: result.rawId,
      ...(result.screenshotRawId ? { screenshotRawId: result.screenshotRawId } : {}),
      note: [
        "Every request above went through Penteos's proxy: they are in proxy_history and the endpoints in the graph.",
        r.dialogs.length ? "The page opened dialogs (listed in dialogs): if you injected the text they show, that is script execution in the page - save the screenshot or this rawId as evidence." : "",
        blocked ? `${blocked} request(s) answered 403: possibly the proxy blocking an out-of-scope host.` : "",
        result.screenshotRawId ? "The screenshot is a raw artifact: cite it with evidence_from_raw (screenshotRawId)." : "",
      ]
        .filter(Boolean)
        .join(" "),
    };
  }
  if (result.status === "apispec") {
    return {
      status: result.error ? "failed" : "done",
      runId: result.run.id,
      ...(result.error ? { error: result.error } : {}),
      ...(result.rawId ? { rawId: result.rawId } : {}),
      ...(result.routes
        ? {
            title: result.title ?? null,
            routes: result.routes.length,
            sample: result.routes.slice(0, 60),
            note: "Every route is now in the graph with its methods, parameters and declared authentication. Next: web_probe_endpoints on this origin (no paths: it takes them all) to find the ones that answer without credentials; then test authorization with real tokens if you have them. The open contract itself was recorded as an observation.",
          }
        : {}),
    };
  }
  if (result.status === "probe") {
    return {
      status: result.error ? "failed" : "done",
      runId: result.run.id,
      ...(result.rawId ? { rawId: result.rawId } : {}),
      ...(result.error ? { error: result.error } : {}),
      ...(result.results
        ? {
            probed: result.results.length,
            ...(result.basePath ? { basePath: result.basePath, baseTrials: result.baseTrials } : {}),
            modeStatus: result.modeStatus ?? null,
            withoutAuth: result.open ?? [],
            results: result.results.slice(0, 300),
            note: (result.open?.length ?? 0) > 0 ? "Endpoints answered without credentials where their siblings refuse: verify each exposes data or an action, then propose findings." : "No endpoint answered without credentials where the rest refuse.",
          }
        : {}),
    };
  }
  if (result.status === "plugin_installed") return result;
  if (result.status === "gap") {
    return {
      status: "gap",
      gapId: result.gap.id,
      ...(result.approval ? { approvalId: result.approval.id } : {}),
      note: `Nothing installed can do this, and Penteos has no way of its own: it is recorded as gap ${result.gap.id} and will be resumed by itself when the tool is installed${result.approval ? " (an install card is waiting for the operator)" : ""}. Do NOT retry it: keep working on something else.`,
    };
  }
  if (result.alreadyRunning) {
    return { status: "running", runId: result.run.id, note: "This exact command is already running (approved earlier). It was not started again: wait for it with run_wait." };
  }
  return { status: "running", runId: result.run.id, targets: result.run.targets, risk: result.run.risk };
}

export const MAX_OUTPUT_FOR_AGENTS = 20_000;
/** An HTTP body kept whole up to this size; the model side shrinks it by structure. */
const MAX_BODY = 2_000_000;

/**
 * How long an agent's call may block on a run. Longer and the conversation goes silent for
 * minutes (an nmap -sV behind a CDN): past this the call returns "running", the agent keeps
 * talking or working, and it is told when the run finishes.
 */
export const AGENT_MAX_WAIT_SECONDS = 90;

/** Status and output of a run, for operations that wait for it to finish. */
export async function settle(ctx: OperationContext, engagementId: string | undefined, runId: string, requested: number) {
  const agent = ctx.caller.actor.type === "agent";
  const seconds = agent ? Math.min(requested, AGENT_MAX_WAIT_SECONDS) : requested;
  const runner = ctx.runner(engagementId);
  const engagement = ctx.engagement(engagementId);
  const run = await runner.waitForRun(runId, seconds);
  if (!run) throw new OperationError("NOT_FOUND", `run not found: ${runId}`);
  let output = "";
  if (run.status === "running") output = runner.liveOutput(runId) ?? "";
  else {
    const raw = run.rawIds.find((r) => r.startsWith("sha256:"));
    if (raw) output = engagement.readRaw(raw).toString("utf8");
  }
  const truncated = output.length > MAX_OUTPUT_FOR_AGENTS;
  return {
    runId: run.id,
    status: run.status,
    ...(run.exitCode !== undefined ? { exitCode: run.exitCode } : {}),
    ...(run.summary ? { summary: run.summary } : {}),
    ...(run.status === "running"
      ? {
          note: agent
            ? `Still running after ${seconds}s. You will be told when it finishes (a "[Penteos" news message), so do not poll with run_wait. Meanwhile tell the operator in one line what is running and why, and continue with other work that does not depend on it.`
            : `still running after ${seconds}s; call run_wait again`,
        }
      : {}),
    output: untrusted(ctx, truncated ? `${output.slice(0, MAX_OUTPUT_FOR_AGENTS)}\n… [${output.length} chars; read the rest with run_output]` : output),
  };
}

export const wait = z
  .number()
  .int()
  .min(0)
  .max(600)
  .optional()
  .describe(`Seconds to wait for the run to finish and return its output in the same call. Use it for quick commands (dig, curl…) instead of polling. Agents wait at most ${AGENT_MAX_WAIT_SECONDS}s; longer runs keep going and you are told when they finish.`);

