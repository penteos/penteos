import { ulid } from "@penteos/schema";
import { z } from "zod";
import { defineOperation, OperationError } from "../registry.js";
import { engagementId } from "./shared.js";
import { findingsToDeepen } from "../../impact.js";
import { untriagedObservations } from "./phases.js";

// ---------------------------------------------------------------------------------------------
// Where we stand and where to go next: a pentest is never done in one pass.
// The Maestro closes a round with a short status and the paths worth exploring; the operator picks
// one, or turns what depends on the client into questions for them.

const PathNeeds = z.enum(["nothing", "approval", "browser", "credentials", "client"]);

export const ExplorationPath = z.object({
  title: z.string().min(1).max(120),
  /** The hypothesis: what makes this worth a look. */
  why: z.string().min(1).max(400),
  /** What would change if it pans out (a severity, a new finding, coverage of an asset). */
  payoff: z.string().max(240).optional(),
  needs: PathNeeds,
  /** How much traffic and attention it costs on the target. */
  noise: z.enum(["low", "medium", "high"]).default("low"),
  /** For needs credentials/client: the question to put to the client, ready to send. */
  question: z.string().max(400).optional(),
  /** The finding whose impact this path would measure (reach, what the exposed data allows, chains). */
  findingId: z.string().optional(),
});
export type ExplorationPath = z.infer<typeof ExplorationPath>;

export interface ClientQuestion {
  id: string;
  text: string;
  /** Quick-reply options for the answer (buttons); free text is always available too. */
  options?: string[];
  /** The path it came from, if any. */
  path?: string;
  createdAt: string;
  createdBy: { type: string; id: string };
  status: "open" | "answered" | "dropped";
  answer?: string;
  answeredAt?: string;
}

defineOperation({
  name: "plan.propose_paths",
  title: "Propose paths to explore",
  description:
    "Closes a round of work with where things stand and the paths worth exploring next, shown to the operator as one card they act on: follow a path, or turn it into a question for the client. Use it when a phase or a line of work ends, when you run out of planned work, and whenever the operator asks what is left or what is worth looking at - never push the report instead. 2-6 paths, best first: each a concrete hypothesis grounded in what was seen (entities, responses, findings), what it could change, and what it needs. Do not list paths already refuted.",
  kind: "write",
  actors: ["agent"],
  input: z.object({
    engagementId,
    status: z.string().min(1).max(800).describe("Where we stand, in 2-4 sentences: what holds, what was ruled out, what could not be tested and why."),
    paths: z.array(ExplorationPath).min(2).max(6),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    // A round does not close on a serious finding whose impact nobody measured: answer its questions
    // now, or, when that needs something you lack, make it one of the paths (with its findingId).
    const pending = findingsToDeepen(e).filter((f) => !input.paths.some((p) => p.findingId === f.id));
    if (pending.length) {
      throw new OperationError(
        "VALIDATION_ERROR",
        `${pending.length} finding(s) still have open impact questions: ${pending
          .slice(0, 5)
          .map((f) => `«${f.title}» (${f.id}: ${f.open.join(", ")})`)
          .join("; ")}. Answer them first (finding_impact gives the leads and the tools; finding_answer_impact records each answer, not_applicable with the reason when one does not apply). If answering needs credentials, approval or the client, make it a path with findingId set.`,
      );
    }
    // Nor does it close on high-signal observations nobody acted on: the verifier only checks
    // findings, so an un-promoted high observation gets no second look. Promote or dismiss it.
    const loose = untriagedObservations(e);
    if (loose.length) {
      throw new OperationError(
        "VALIDATION_ERROR",
        `${loose.length} high-signal observation(s) are neither promoted nor dismissed: ${loose
          .slice(0, 6)
          .map((o) => `«${o.title}»`)
          .join("; ")}. Decide on each: promote the real ones (observation_promote → the verifier checks them), or dismiss the rest with observation_triage (false_positive / duplicate / accepted_risk) and a reason. Nothing high-signal should sit unreviewed.`,
      );
    }
    const proposal = { id: ulid(), at: new Date().toISOString(), by: ctx.caller.actor, status: input.status, paths: input.paths };
    e.setState("paths", proposal);
    e.audit(ctx.caller.actor, "plan.propose_paths", { proposal: proposal.id }, proposal);
    return { status: "shown", id: proposal.id, paths: input.paths.length, note: "The operator sees the card. Wait for them: do not start any path on your own, and do not repeat the paths in your message." };
  },
});

function questions(e: { getState<T>(k: string): T | undefined }): ClientQuestion[] {
  return e.getState<ClientQuestion[]>("clientQuestions") ?? [];
}

defineOperation({
  name: "client_question.list",
  title: "Questions for the client",
  description: "What the team needs to ask the client (accounts, maintenance windows, what a service protects) and the answers already received.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => questions(ctx.engagement(input.engagementId)),
});

defineOperation({
  name: "client_question.add",
  title: "Add a question for the client",
  description: "Adds a question for the client to the list the operator sends them. One question each, concrete and answerable.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, text: z.string().min(1).max(400), options: z.array(z.string().min(1).max(120)).min(2).max(4).optional(), path: z.string().max(120).optional() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const list = questions(e);
    const same = list.find((q) => q.status === "open" && q.text.trim().toLowerCase() === input.text.trim().toLowerCase());
    if (same) return same;
    const q: ClientQuestion = { id: ulid(), text: input.text.trim(), ...(input.options?.length ? { options: input.options } : {}), ...(input.path ? { path: input.path } : {}), createdAt: new Date().toISOString(), createdBy: ctx.caller.actor, status: "open" };
    e.setState("clientQuestions", [...list, q]);
    e.audit(ctx.caller.actor, "client_question.add", { question: q.id }, q);
    e.emit({ type: "client_questions.changed" });
    return q;
  },
});

defineOperation({
  name: "client_question.answer",
  title: "Record the client's answer",
  description: "Records what the client answered (or drops the question). The Maestro hears the answer.",
  kind: "write",
  actors: ["human"],
  input: z.object({ engagementId, id: z.string(), answer: z.string().max(2000).optional(), drop: z.boolean().default(false) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const list = questions(e);
    const q = list.find((x) => x.id === input.id);
    if (!q) throw new OperationError("NOT_FOUND", `question not found: ${input.id}`);
    if (!input.drop && !input.answer?.trim()) throw new OperationError("VALIDATION_ERROR", "an answer, or drop: true");
    const updated: ClientQuestion = input.drop ? { ...q, status: "dropped" } : { ...q, status: "answered", answer: input.answer!.trim(), answeredAt: new Date().toISOString() };
    e.setState("clientQuestions", list.map((x) => (x.id === q.id ? updated : x)));
    e.audit(ctx.caller.actor, "client_question.answer", { question: q.id }, updated);
    e.emit({ type: "client_questions.changed" });
    if (!input.drop) e.emit({ type: "client_question.answered", id: q.id, question: q.text, answer: updated.answer!, by: ctx.caller.actor });
    return updated;
  },
});
