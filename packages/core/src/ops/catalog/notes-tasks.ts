import { defineOperation, OperationError, type OperationContext } from "../registry.js";
import { EntityKind, isPluginKind } from "@penteos/schema";
import { z } from "zod";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// Notes and the task board

/** Mentions written as markdown links: [@label](penteos:entity/<id>). */
export function mentionsIn(engagement: ReturnType<OperationContext["engagement"]>, text: string): Array<{ kind: EntityKind; id: string }> {
  const ids = [...new Set([...text.matchAll(/\(penteos:entity\/([0-9A-HJKMNP-TV-Z]{26})\)/g)].map((m) => m[1]!))];
  return ids.flatMap((id) => {
    const e = engagement.get(id);
    // A plugin entity stays a link in the text; the structured list keeps official kinds only, so a
    // note never depends on a plugin being installed.
    return e && !isPluginKind(e.kind) ? [{ kind: e.kind, id: e.id }] : [];
  });
}

const MENTION_HELP = "Mention entities as markdown links [@label](penteos:entity/<id>) - the operator can click them.";

defineOperation({
  name: "note.create",
  title: "Create note",
  description: `Creates a markdown note in the engagement (shared with the team). ${MENTION_HELP}`,
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, title: z.string().min(1), body: z.string().default("") }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    return e.createEntity("note", { title: input.title, body: input.body, mentions: mentionsIn(e, input.body) }, ctx.caller.actor);
  },
});

defineOperation({
  name: "note.update",
  title: "Edit note",
  description: `Changes a note's title or body. ${MENTION_HELP}`,
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, id: z.string(), title: z.string().min(1).optional(), body: z.string().optional() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const note = e.get(input.id);
    if (!note || note.kind !== "note") throw new OperationError("NOT_FOUND", `note ${input.id} not found`);
    return e.editEntity(
      input.id,
      { ...(input.title ? { title: input.title } : {}), ...(input.body !== undefined ? { body: input.body, mentions: mentionsIn(e, input.body) } : {}) },
      ctx.caller.actor,
    );
  },
});

const TaskStatus = z.enum(["todo", "in_progress", "blocked", "awaiting_approval", "done", "cancelled"]);
const Priority = z.enum(["low", "normal", "high", "urgent"]);
const Assignee = z
  .enum(["me", "maestro", "operator", "nobody"])
  .or(z.string().regex(/^[0-9A-Z]{26}$/))
  .describe('"me" (whoever calls), "maestro", "operator" (the human running this workspace), "nobody" or an operator id');

function assigneeOf(ctx: OperationContext, a: string | undefined) {
  if (!a || a === "nobody") return undefined;
  if (a === "me") return ctx.caller.actor;
  if (a === "maestro") return { type: "agent" as const, id: "01JA000000000000000000MSTR" };
  if (a === "operator") return { type: "human" as const, id: "01JA0000000000000000000HMN" };
  return { type: "human" as const, id: a };
}

defineOperation({
  name: "task.create",
  title: "Create task",
  description: `Adds a task to the board shared by humans and agents: a concrete piece of work ("probar IDOR en /api/orders"), with priority and who does it. ${MENTION_HELP}`,
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    title: z.string().min(1),
    description: z.string().optional(),
    priority: Priority.default("normal"),
    assignee: Assignee.optional(),
    question: z
      .string()
      .max(2000)
      .optional()
      .describe('When you need a decision from the operator: the question, short and answerable (write it in the project language). Assign it to "operator". The operator answers on the card and you receive the answer as news; do not ask the same thing in the chat too.'),
    options: z
      .array(z.string().min(1).max(120))
      .min(2)
      .max(4)
      .optional()
      .describe('2-4 quick-reply buttons for a choice question (e.g. ["Yes, test it", "No, skip it"] or the scopes/approaches to pick from), in the project language. The operator can still type a free answer. Omit options when you are asking for a value the operator must type - a credential, an account, a URL, a maintenance window.'),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const assignee = assigneeOf(ctx, input.assignee);
    return e.createEntity(
      "task",
      {
        title: input.title,
        ...(input.description ? { description: input.description } : {}),
        priority: input.priority,
        status: "todo",
        ...(assignee ? { assignee } : {}),
        ...(input.question ? { question: input.question } : {}),
        ...(input.question && input.options?.length ? { options: input.options } : {}),
        related: mentionsIn(e, `${input.title} ${input.description ?? ""}`),
      },
      ctx.caller.actor,
    );
  },
});

defineOperation({
  name: "task.update",
  title: "Update task",
  description: "Moves a task on the board (todo, in_progress, blocked, done, cancelled) or changes its title, priority or assignee.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    id: z.string(),
    status: TaskStatus.optional(),
    title: z.string().min(1).optional(),
    description: z.string().optional(),
    priority: Priority.optional(),
    assignee: Assignee.optional(),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const task = e.get(input.id);
    if (!task || task.kind !== "task") throw new OperationError("NOT_FOUND", `task ${input.id} not found`);
    const assignee = input.assignee !== undefined ? assigneeOf(ctx, input.assignee) : undefined;
    return e.editEntity(
      input.id,
      {
        ...(input.status ? { status: input.status } : {}),
        ...(input.title ? { title: input.title } : {}),
        ...(input.description !== undefined ? { description: input.description } : {}),
        ...(input.priority ? { priority: input.priority } : {}),
        ...(input.assignee !== undefined ? { assignee: assignee ?? null } : {}),
      },
      ctx.caller.actor,
    );
  },
});

defineOperation({
  name: "task.list",
  title: "Task board",
  description: "The tasks of the engagement with status, priority and assignee. Check it when you start: someone may have left work for you.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, status: TaskStatus.optional() }),
  handler: (input, ctx) =>
    ctx
      .engagement(input.engagementId)
      .query({ kind: "task", limit: 2000 })
      .filter((t) => !input.status || t.attributes.status === input.status),
});

defineOperation({
  name: "task.answer",
  title: "Answer a task's question",
  description: "The operator answers the decision an agent asked for on the board. The task is closed with the answer and the agent that asked receives it as news.",
  kind: "write",
  actors: ["human"],
  input: z.object({ engagementId, id: z.string(), answer: z.string().min(1).max(4000) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const task = e.get(input.id);
    if (!task || task.kind !== "task") throw new OperationError("NOT_FOUND", `task ${input.id} not found`);
    const question = String(task.attributes.question ?? task.attributes.title);
    const edited = e.editEntity(input.id, { status: "done", answer: { text: input.answer, by: ctx.caller.actor, at: new Date().toISOString() } }, ctx.caller.actor);
    e.emit({ type: "task.answered", taskId: input.id, title: String(task.attributes.title), question, answer: input.answer, by: ctx.caller.actor, ...(task.createdBy.type === "agent" ? { askedBy: task.createdBy } : {}) });
    return edited;
  },
});

defineOperation({
  name: "task.delete",
  title: "Delete task",
  description: "Removes a task from the board. It stays in the audit trail.",
  kind: "write",
  actors: ["human"],
  input: z.object({ engagementId, id: z.string() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const task = e.get(input.id);
    if (!task || task.kind !== "task") throw new OperationError("NOT_FOUND", `task ${input.id} not found`);
    e.deleteTask(input.id, ctx.caller.actor);
    return { status: "deleted" };
  },
});
