import type { RunOutcome } from "../../tools/runner.js";
import { defineOperation, OperationError } from "../registry.js";
import { RiskLevel } from "@penteos/schema";
import { z } from "zod";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { engagementId, outcome, untrusted } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// WebSocket: messages seen by the proxy, and the WebSocket repeater

defineOperation({
  name: "ws.messages",
  title: "WebSocket messages",
  description: "Messages of a WebSocket connection (a proxy history entry): direction (out: client→server, in: server→client), text (or base64 when binary), size and whether it was edited.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, entryId: z.string(), afterSeq: z.number().int().min(0).default(0), limit: z.number().int().min(1).max(10_000).default(500) }),
  handler: (input, ctx) =>
    ctx
      .engagement(input.engagementId)
      .queryWs(input.entryId, { afterSeq: input.afterSeq, limit: input.limit })
      .map((m) => ({ ...m, data: untrusted(ctx, m.data) })),
});

defineOperation({
  name: "ws.open",
  title: "Open a WebSocket",
  description:
    "Opens a WebSocket connection from Penteos to an in-scope ws:// or wss:// URL (headers such as Cookie or Origin as 'Name: value' lines; use {{secret:name}}). Messages are recorded; send with ws_send, read with ws_messages.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, url: z.string(), headers: z.string().default(""), risk: RiskLevel.default("active") }),
  handler: async (input, ctx) => {
    const headers = input.headers
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.includes(":"))
      .map((l) => [l.slice(0, l.indexOf(":")).trim(), l.slice(l.indexOf(":") + 1).trim()] as [string, string]);
    let result: RunOutcome;
    try {
      result = await ctx.runner(input.engagementId).openWs({ url: input.url, headers, risk: input.risk }, { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" });
    } catch (e) {
      if (e instanceof OperationError) throw e;
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
    return outcome(result, ctx);
  },
});

defineOperation({
  name: "ws.send",
  title: "Send a WebSocket message",
  description: "Sends a text message (or binary, as base64) on a WebSocket opened with ws_open. {{secret:name}} is substituted.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, sessionId: z.string(), text: z.string().optional(), base64: z.string().optional() }),
  handler: (input, ctx) => {
    try {
      ctx.runner(input.engagementId).sendWs(input.sessionId, { ...(input.text !== undefined ? { text: input.text } : {}), ...(input.base64 !== undefined ? { base64: input.base64 } : {}) });
    } catch (e) {
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
    return { status: "sent" };
  },
});

defineOperation({
  name: "ws.close",
  title: "Close a WebSocket",
  description: "Closes a WebSocket opened with ws_open.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({ engagementId, sessionId: z.string() }),
  handler: (input, ctx) => ({ closed: ctx.runner(input.engagementId).closeWs(input.sessionId) }),
});

defineOperation({
  name: "ws.sessions",
  title: "Open WebSockets",
  description: "WebSocket connections opened from Penteos that are still open.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => ctx.runner(input.engagementId).wsList(),
});
