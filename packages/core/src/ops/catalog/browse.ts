import { z } from "zod";
import { defineOperation, OperationError } from "../registry.js";
import { engagementId } from "./shared.js";

/**
 * Browsing on request: some things only a person at a real browser can do - a
 * JavaScript anti-bot challenge, an MFA step, a login with a captcha. The agent asks with the URL
 * and the steps; the operator opens the project browser from the request, its traffic is recorded
 * by the proxy, and when they say it is done the agent hears how much was captured and where.
 */

const OPERATOR = { type: "human" as const, id: "01JA0000000000000000000HMN" };

defineOperation({
  name: "browser.request",
  title: "Ask the operator to browse",
  description:
    "Asks the operator to browse something in the project browser when automated requests cannot (a JavaScript challenge, a login with captcha or MFA, a multi-step flow). Give the URL to start from and short, concrete steps in the project language. The operator sees the request with a button that opens the browser there, with your steps on screen; everything they browse is recorded by the proxy. When they finish you receive the number of exchanges and the hosts: read them with proxy_history. Do not also ask in the chat.",
  kind: "write",
  actors: ["agent"],
  input: z.object({
    engagementId,
    url: z.string().url().describe("Where to start, inside the scope"),
    title: z.string().min(1).max(120).describe("What you need, in one line (project language), e.g. 'Pasar el reto anti-bot de arbitraje y recorrer el login'"),
    steps: z.array(z.string().min(1).max(300)).min(1).max(8).describe("What to do, one step per item, short and concrete (project language)"),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const decision = e.checkScope(input.url, "passive", { type: "human" });
    if (decision.decision === "deny") throw new OperationError("OUT_OF_SCOPE", `${input.url} is out of scope: ${decision.reason}`);
    const origin = new URL(input.url).origin;
    const open = e
      .query({ kind: "task", limit: 2000 })
      .find((t) => {
        const b = t.attributes.browse as { url: string } | undefined;
        return b && !["done", "cancelled"].includes(String(t.attributes.status)) && new URL(b.url).origin === origin;
      });
    if (open) return { taskId: open.id, status: "already_requested", note: "There is already an open browsing request for this site; it was not created again. Wait for the operator." };
    const task = e.createEntity(
      "task",
      {
        title: input.title,
        priority: "high",
        status: "todo",
        assignee: OPERATOR,
        browse: { url: input.url, steps: input.steps, requestedAt: new Date().toISOString() },
        related: [],
      },
      ctx.caller.actor,
    );
    return { taskId: task.id, status: "requested" };
  },
});

defineOperation({
  name: "browser.respond",
  title: "Answer a browsing request",
  description: "The operator says they finished browsing what an agent asked for (or declines). The task closes and the agent hears how many exchanges the proxy recorded since the request, and on which hosts.",
  kind: "write",
  actors: ["human"],
  input: z.object({ engagementId, taskId: z.string(), outcome: z.enum(["done", "declined"]), note: z.string().max(2000).optional() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const task = e.get(input.taskId);
    const browse = task?.attributes.browse as { url: string; steps: string[]; requestedAt: string } | undefined;
    if (!task || task.kind !== "task" || !browse) throw new OperationError("NOT_FOUND", `browsing request ${input.taskId} not found`);
    const captured = e.queryProxy({ limit: 5000, includeStatic: true }).filter((x) => x.at >= browse.requestedAt && !x.blocked);
    const hosts = [...new Set(captured.map((x) => x.host))].slice(0, 20);
    const at = new Date().toISOString();
    const result = { outcome: input.outcome, exchanges: captured.length, hosts, ...(input.note ? { note: input.note } : {}), by: ctx.caller.actor, at };
    const edited = e.editEntity(input.taskId, { status: input.outcome === "done" ? "done" : "cancelled", browse: { ...browse, result } }, ctx.caller.actor);
    e.emit({
      type: "browse.responded",
      taskId: input.taskId,
      title: String(task.attributes.title),
      outcome: input.outcome,
      exchanges: captured.length,
      hosts,
      ...(input.note ? { note: input.note } : {}),
      by: ctx.caller.actor,
      ...(task.createdBy.type === "agent" ? { askedBy: task.createdBy } : {}),
    });
    return { task: edited, exchanges: captured.length, hosts };
  },
});

defineOperation({
  name: "browser.progress",
  title: "Traffic captured for a browsing request",
  description: "How many exchanges the proxy recorded since a browsing request was made, and on which hosts. The browser shows it live while the operator works.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, taskId: z.string() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const browse = e.get(input.taskId)?.attributes.browse as { requestedAt: string } | undefined;
    if (!browse) throw new OperationError("NOT_FOUND", `browsing request ${input.taskId} not found`);
    const captured = e.queryProxy({ limit: 5000, includeStatic: true }).filter((x) => x.at >= browse.requestedAt && !x.blocked);
    return { exchanges: captured.length, hosts: [...new Set(captured.map((x) => x.host))].slice(0, 20) };
  },
});
