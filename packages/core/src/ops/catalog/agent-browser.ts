import { RiskLevel } from "@penteos/schema";
import { z } from "zod";
import type { BrowseAction } from "../../browser/agent-browser.js";
import { defineOperation, type OperationContext, OperationError } from "../registry.js";
import { engagementId, outcome } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// The agents' own browser. Not to be confused with browser.request,
// which asks the OPERATOR to browse something only a person can (captchas, MFA, anti-bot).

const wait = z.number().int().min(0).max(30_000).optional().describe("How long to let the page settle after the action, in ms (default: until the network is quiet, at most 8 s)");

async function act(ctx: OperationContext, id: string | undefined, action: BrowseAction, risk: z.infer<typeof RiskLevel>) {
  try {
    const result = await ctx.runner(id).browse({ action, risk }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" });
    return outcome(result, ctx);
  } catch (e) {
    if (e instanceof OperationError) throw e;
    throw new OperationError("VALIDATION_ERROR", (e as Error).message);
  }
}

const COMMON =
  "Penteos's own headless browser, run by you: it executes the page's JavaScript and keeps its session (cookies, storage) between calls, and every request it makes goes through Penteos's proxy (scope, history, evidence). Returns what the page shows (text, links, forms with selectors, buttons), the requests it caused, any dialogs it opened and console errors.";

defineOperation({
  name: "browser.open",
  title: "Open a page in the agents' browser",
  description: `${COMMON} Open a URL in scope. Use it for single-page applications and flows that only exist when the JavaScript runs (routes, API calls made on click, multi-step logins with test accounts), and to check client-side behaviour for real. For anything only a person can do (captcha, MFA, anti-bot challenge) use browser_request instead.`,
  kind: "target",
  risk: "active",
  actors: ["human", "agent"],
  input: z.object({ engagementId, url: z.string().url(), waitMs: wait, risk: RiskLevel.default("active") }),
  handler: (input, ctx) => act(ctx, input.engagementId, { action: "visit", url: input.url, ...(input.waitMs !== undefined ? { waitMs: input.waitMs } : {}) }, input.risk),
});

defineOperation({
  name: "browser.click",
  title: "Click in the agents' browser",
  description: `${COMMON} Click an element of the open page: by CSS selector (from the forms and buttons browser_open returned) or by its visible text.`,
  kind: "target",
  risk: "active",
  actors: ["human", "agent"],
  input: z.object({ engagementId, selector: z.string().min(1).optional(), text: z.string().min(1).optional(), waitMs: wait, risk: RiskLevel.default("active") }).refine((v) => v.selector || v.text, "a selector or a text"),
  handler: (input, ctx) =>
    act(ctx, input.engagementId, { action: "click", ...(input.selector ? { selector: input.selector } : {}), ...(input.text ? { text: input.text } : {}), ...(input.waitMs !== undefined ? { waitMs: input.waitMs } : {}) }, input.risk),
});

defineOperation({
  name: "browser.fill",
  title: "Fill a field in the agents' browser",
  description: `${COMMON} Type a value into a field of the open page (frameworks see it as typed), optionally submitting its form. Credentials go as {{secret:name}}: Penteos types the value and never records it.`,
  kind: "target",
  risk: "active",
  actors: ["human", "agent"],
  input: z.object({ engagementId, selector: z.string().min(1), value: z.string(), submit: z.boolean().default(false), waitMs: wait, risk: RiskLevel.default("active") }),
  handler: (input, ctx) =>
    act(ctx, input.engagementId, { action: "fill", selector: input.selector, value: input.value, submit: input.submit, ...(input.waitMs !== undefined ? { waitMs: input.waitMs } : {}) }, input.risk),
});

defineOperation({
  name: "browser.read",
  title: "Read the page in the agents' browser",
  description: `${COMMON} Read the open page again as it is now (after it changed by itself), without acting on it.`,
  kind: "target",
  risk: "passive",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => act(ctx, input.engagementId, { action: "read" }, "passive"),
});

defineOperation({
  name: "browser.screenshot",
  title: "Screenshot in the agents' browser",
  description: `${COMMON} Take a screenshot of the open page. It is stored as a raw artifact (screenshotRawId): cite it with evidence_from_raw so the finding and the report show what you saw.`,
  kind: "target",
  risk: "passive",
  actors: ["human", "agent"],
  input: z.object({ engagementId, fullPage: z.boolean().default(false) }),
  handler: (input, ctx) => act(ctx, input.engagementId, { action: "screenshot", fullPage: input.fullPage }, "passive"),
});
