import type { Entity } from "./state";

/**
 * When a task waits for the operator's answer. An agent asks with `question`, but any open task an
 * agent assigned to a human is a request for a decision too (older tasks, or an agent that forgot
 * the field): it gets the same answer box, so nothing an agent asked is left without a way to reply.
 */
export function asksOperator(t: Entity): boolean {
  if (["done", "cancelled"].includes(String(t.attributes.status)) || t.attributes.answer) return false;
  if (t.attributes.question) return true;
  const a = t.attributes.assignee as { type: string } | null | undefined;
  return a?.type === "human" && t.createdBy.type === "agent";
}

/** What the agent asked, in one line, and the detail it left with it. */
export function questionOf(t: Entity): { question: string; detail?: string } {
  const q = t.attributes.question ? String(t.attributes.question) : String(t.attributes.title);
  const d = t.attributes.description ? String(t.attributes.description).trim() : "";
  return d && d !== q ? { question: q, detail: d.length > 400 ? `${d.slice(0, 400)}…` : d } : { question: q };
}
