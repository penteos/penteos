import { defineOperation, OperationError, type OperationContext } from "../registry.js";
import { z } from "zod";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// Agent memory: what the graph does not capture - attempts that failed,
// decisions and their reasons, open hypotheses. Visible and editable by the team.

const MEMORY_TYPES = ["fact", "decision", "attempt", "hypothesis", "preference", "lesson"] as const;

/** A memory tied to entities that changed after it was written may no longer hold. */
function withFreshness(e: ReturnType<OperationContext["engagement"]>, m: ReturnType<typeof e.get> & object) {
  const a = m.attributes as { entities?: Array<{ id: string }>; validity?: { type: string; at?: string } };
  const changed = (a.entities ?? []).some((ref) => {
    const ent = e.get(ref.id);
    return ent ? ent.updatedAt > m.createdAt : false;
  });
  const expired = a.validity?.type === "expires" && a.validity.at !== undefined && a.validity.at < new Date().toISOString();
  return { ...m, reverify: (a.validity?.type === "until_reverified" && changed) || expired };
}

defineOperation({
  name: "memory.write",
  title: "Remember",
  description:
    'Records what the graph does not capture, so nobody repeats it: "attempt" (what was tried and how it went, e.g. "sqlmap on /login: blocked by WAF after 15 requests"), "decision" (and why), "hypothesis" (to check later), "fact", "lesson". Link the entities it is about. Write one after any failed attempt or decision that matters.',
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    memoryType: z.enum(MEMORY_TYPES),
    content: z.string().min(1).max(2000),
    entityIds: z.array(z.string()).default([]),
    rawRef: z.string().optional().describe("sha256 of the raw output that backs it"),
    validity: z.enum(["permanent", "until_reverified"]).default("until_reverified"),
    confidence: z.number().min(0).max(1).default(0.8),
    fromTarget: z.boolean().default(false).describe("true when it comes from what the target said (not verified by you)"),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const entities = input.entityIds.flatMap((id) => {
      const x = e.get(id);
      return x ? [{ kind: x.kind, id: x.id }] : [];
    });
    return e.createEntity(
      "memory",
      {
        memoryType: input.memoryType,
        scope: "engagement",
        content: input.content,
        entities,
        ...(input.rawRef ? { rawRef: input.rawRef } : {}),
        validity: { type: input.validity },
        confidence: input.confidence,
        // Prompt-injection defense: an agent's memory derived from target content is never trusted.
        trusted: !(input.fromTarget || false),
      },
      ctx.caller.actor,
    );
  },
});

defineOperation({
  name: "memory.query",
  title: "Recall",
  description:
    "What the team (humans and agents) remembers about this engagement: attempts, decisions, hypotheses. Filter by entity, type or text. Check it before trying something on an entity - it may have been tried already. Entries marked reverify=true are about something that changed since.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    entityId: z.string().optional(),
    memoryType: z.enum(MEMORY_TYPES).optional(),
    text: z.string().optional(),
    includeInvalidated: z.boolean().default(false),
    limit: z.number().int().min(1).max(500).default(100),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const t = input.text?.toLowerCase();
    return e
      .query({ kind: "memory", limit: 10_000 })
      .filter((m) => {
        const a = m.attributes as { memoryType: string; content: string; entities: Array<{ id: string }>; invalidated?: unknown };
        if (!input.includeInvalidated && a.invalidated) return false;
        if (input.memoryType && a.memoryType !== input.memoryType) return false;
        if (input.entityId && !a.entities.some((x) => x.id === input.entityId)) return false;
        if (t && !a.content.toLowerCase().includes(t)) return false;
        return true;
      })
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, input.limit)
      .map((m) => withFreshness(e, m));
  },
});

defineOperation({
  name: "memory.update",
  title: "Correct a memory",
  description: "Corrects the content of a memory entry, or marks it as no longer true (invalidate) with a reason.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, id: z.string(), content: z.string().min(1).optional(), invalidate: z.string().optional().describe("Reason it no longer holds") }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const m = e.get(input.id);
    if (!m || m.kind !== "memory") throw new OperationError("NOT_FOUND", `memory ${input.id} not found`);
    return e.editEntity(
      input.id,
      {
        ...(input.content ? { content: input.content } : {}),
        ...(input.invalidate ? { invalidated: { at: new Date().toISOString(), reason: input.invalidate } } : {}),
      },
      ctx.caller.actor,
    );
  },
});
