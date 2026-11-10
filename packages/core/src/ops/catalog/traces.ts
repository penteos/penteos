import { ulid } from "@penteos/schema";
import { z } from "zod";
import { defineOperation, OperationError } from "../registry.js";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// Traces left on the target: a test that creates something in the client's
// systems - a subscription, an account, an uploaded file, a record, an email sent - leaves it
// there. Each one is written down when it happens, and the report lists what is still to clean.

export interface Trace {
  id: string;
  /** What was left, concretely: "the address prueba1@example.com subscribed to the blog". */
  what: string;
  /** Where: the endpoint, host or application. */
  where: string;
  /** How to remove it, if known. */
  cleanup?: string;
  at: string;
  by: { type: string; id: string };
  status: "pending" | "cleaned" | "accepted";
  note?: string;
}

const list = (e: { getState<T>(k: string): T | undefined }) => e.getState<Trace[]>("traces") ?? [];

defineOperation({
  name: "trace.record",
  title: "Record a trace left on the target",
  description:
    "Writes down something a test left in the client's systems: a subscription, an account or record created, a file uploaded, an email or message sent, a setting changed. Call it right after the action that left it. The report lists the traces still pending cleanup.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, what: z.string().min(1).max(300), where: z.string().min(1).max(300), cleanup: z.string().max(300).optional() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const t: Trace = { id: ulid(), what: input.what.trim(), where: input.where.trim(), ...(input.cleanup ? { cleanup: input.cleanup.trim() } : {}), at: new Date().toISOString(), by: ctx.caller.actor, status: "pending" };
    e.setState("traces", [...list(e), t]);
    e.audit(ctx.caller.actor, "trace.record", { trace: t.id }, t);
    e.emit({ type: "traces.changed" });
    return t;
  },
});

defineOperation({
  name: "trace.list",
  title: "Traces left on the target",
  description: "What the tests left in the client's systems and whether it was cleaned.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => list(ctx.engagement(input.engagementId)),
});

defineOperation({
  name: "trace.resolve",
  title: "Mark a trace as cleaned or accepted",
  description: "A person records that a trace was removed, or that the client accepts leaving it.",
  kind: "write",
  actors: ["human"],
  input: z.object({ engagementId, id: z.string(), status: z.enum(["cleaned", "accepted", "pending"]), note: z.string().max(300).optional() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const all = list(e);
    const t = all.find((x) => x.id === input.id);
    if (!t) throw new OperationError("NOT_FOUND", `trace not found: ${input.id}`);
    const updated: Trace = { ...t, status: input.status, ...(input.note ? { note: input.note } : {}) };
    e.setState("traces", all.map((x) => (x.id === t.id ? updated : x)));
    e.audit(ctx.caller.actor, "trace.resolve", { trace: t.id }, updated);
    e.emit({ type: "traces.changed" });
    return updated;
  },
});
