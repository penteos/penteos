import { requireProxy } from "./proxy.js";
import type { RunOutcome } from "../../tools/runner.js";
import { defineOperation, OperationError, type OperationContext } from "../registry.js";
import { ulid } from "@penteos/schema";
import { z } from "zod";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { join } from "node:path";
import { engagementId, outcome, wait } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// Interception and replace rules (proxy, stage 2)

/** The operator turned interception on and something arrived recently: they may be editing it. */
function operatorBusy(e: ReturnType<OperationContext["engagement"]>, i: NonNullable<OperationContext["proxy"]>["interceptor"]): void {
  if (i.settings(e).by === "agent") return;
  const recent = i.list(e.info.id).filter((m) => Date.now() - Date.parse(m.createdAt) < 60_000);
  if (recent.length)
    throw new OperationError(
      "VALIDATION_ERROR",
      `The operator turned interception on and ${recent.length} message(s) arrived less than a minute ago: they may be editing them. Do not release them; ask the operator in your reply, or try again later.`,
    );
}

defineOperation({
  name: "intercept.state",
  title: "Interception",
  description: "Interception settings, the messages waiting in the queue (held flows hang the operator's browser) and the replace rules of this project.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const i = requireProxy(ctx).interceptor;
    const pending = i.list(e.info.id);
    if (ctx.caller.actor.type !== "agent") return { settings: i.settings(e), pending, rules: i.rules(e) };
    // Agents get what is waiting and for how long, not the operator's raw traffic.
    const now = Date.now();
    return {
      settings: i.settings(e),
      pending: pending.map((m) => ({ kind: m.kind, method: m.method, url: m.url, waitingSeconds: Math.round((now - Date.parse(m.createdAt)) / 1000) })),
      rules: i.rules(e),
    };
  },
});

defineOperation({
  name: "intercept.configure",
  title: "Configure interception",
  description:
    "Turns interception of requests and/or responses on or off and sets which messages stop (scope, host, methods, static files). Turning it off lets everything waiting go out unchanged. Held messages wait for the operator in the UI, so only an operator at the screen can edit them: agents turn it on narrowly (hostContains, methods) when the operator will act, and off again when done.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    reason: z.string().max(500).optional().describe("Why (required for agents; shown to the operator)."),
    requests: z.boolean().optional(),
    responses: z.boolean().optional(),
    wsMessages: z.boolean().optional(),
    inScopeOnly: z.boolean().optional(),
    skipStatic: z.boolean().optional(),
    hostContains: z.string().max(200).optional(),
    methods: z.array(z.string()).optional(),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const i = requireProxy(ctx).interceptor;
    const { engagementId: _id, reason, ...patch } = input;
    const agent = ctx.caller.actor.type === "agent";
    if (agent && !reason?.trim()) throw new OperationError("VALIDATION_ERROR", "say why in reason: the operator sees it");
    const before = i.settings(e);
    const next = { ...before, ...Object.fromEntries(Object.entries(patch).filter(([, v]) => v !== undefined)), by: ctx.caller.actor.type === "agent" ? ("agent" as const) : ("human" as const) };
    if (agent && !next.requests && !next.responses && !next.wsMessages) operatorBusy(e, i);
    e.setMeta("intercept", next, ctx.caller.actor);
    const released = !next.requests && !next.responses && !next.wsMessages ? i.releaseAll(e.info.id) : 0;
    e.emit({ type: "intercept.changed" });
    if (agent) {
      const on = [next.requests && "requests", next.responses && "responses", next.wsMessages && "websocket"].filter((x): x is string => Boolean(x));
      e.emit({ type: "proxy.agent_changed", change: "intercept", on, reason, text: `${on.length ? `Interception on (${on.join(", ")})` : "Interception off"}: ${reason}` });
    }
    return { ...next, ...(released ? { released } : {}) };
  },
});

defineOperation({
  name: "intercept.decide",
  title: "Forward or drop an intercepted message",
  description: "Lets an intercepted request or response go (as it was, or with the edited raw text) or drops it.",
  kind: "target",
  actors: ["human"],
  input: z.object({ engagementId, id: z.string(), action: z.enum(["forward", "drop"]), raw: z.string().optional() }),
  handler: (input, ctx) => {
    const i = requireProxy(ctx).interceptor;
    try {
      const ok = i.decide(input.id, input.action === "drop" ? { action: "drop" } : { action: "forward", ...(input.raw !== undefined ? { raw: input.raw } : {}) });
      if (!ok) throw new OperationError("NOT_FOUND", "that message is no longer waiting (it timed out or was already decided)");
    } catch (e) {
      if (e instanceof OperationError) throw e;
      throw new OperationError("VALIDATION_ERROR", `The edited message is not valid: ${(e as Error).message}`);
    }
    return { status: input.action === "drop" ? "dropped" : "forwarded" };
  },
});

defineOperation({
  name: "intercept.release_all",
  title: "Forward everything waiting",
  description: "Lets every intercepted message of this project go out unchanged (unblocks the operator's browser).",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, reason: z.string().max(500).optional() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const i = requireProxy(ctx).interceptor;
    if (ctx.caller.actor.type === "agent") operatorBusy(e, i);
    const released = i.releaseAll(e.info.id);
    if (ctx.caller.actor.type === "agent" && released) e.emit({ type: "proxy.agent_changed", change: "release", count: released, ...(input.reason ? { reason: input.reason } : {}), text: `Released ${released} held message${released === 1 ? "" : "s"}${input.reason ? `: ${input.reason}` : ""}` });
    return { released };
  },
});

const ReplaceRuleInput = z.object({
  id: z.string().optional(),
  enabled: z.boolean().default(true),
  target: z.enum(["request_header", "request_body", "request_url", "response_header", "response_body"]),
  match: z.string().max(2000),
  regex: z.boolean().default(false),
  replace: z.string().max(10_000),
  comment: z.string().max(300).optional(),
});

defineOperation({
  name: "proxy.set_rules",
  title: "Replace rules",
  description:
    "Sets the replace rules of the proxy for this project (the whole list, in order: read the current ones with intercept_state and send them back with your changes). Each rule finds text or a regex in headers, body or URL and replaces it; an empty match on a header target adds that header line. They rewrite every flow the operator browses, automatically: use them instead of editing intercepted messages by hand. Agents without autonomy up to active risk get an approval card.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, rules: z.array(ReplaceRuleInput).max(200), reason: z.string().max(500).optional().describe("Why (required for agents; shown to the operator).") }),
  handler: (input, ctx) => {
    const rules: ReplaceRule[] = input.rules.map((r) => ({ ...r, id: r.id || ulid() }) as ReplaceRule);
    if (ctx.caller.actor.type === "agent" && !input.reason?.trim()) throw new OperationError("VALIDATION_ERROR", "say why in reason: the operator sees it");
    let result: RunOutcome;
    try {
      result = ctx.runner(input.engagementId).setProxyRules(rules, input.reason ?? "", { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" });
    } catch (e) {
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
    return result.status === "rules_set" ? result.rules : outcome(result, ctx);
  },
});
