import { z } from "zod";
import { addRunNote, removeRunNote, runSummary } from "../../metrics.js";
import { defineOperation } from "../registry.js";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// How a run went: measured on real engagements and comparable across them.

defineOperation({
  name: "metrics.summary",
  title: "How the run went",
  description:
    "What this engagement's agents found and the verifier confirmed, what the operator noted they missed, and how they behaved: calls, errors by code, repeated calls echoed or refused, arguments repaired, step limits reached, scope denials.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => runSummary(ctx.engagement(input.engagementId)),
});

defineOperation({
  name: "metrics.compare",
  title: "Compare runs",
  description: "The run summary of every engagement in the workspace, newest first, to compare how the agents did across clients.",
  kind: "read",
  actors: ["human"],
  input: z.object({ limit: z.number().int().min(1).max(200).default(50) }),
  handler: (input, ctx) =>
    ctx.workspace
      .list()
      .slice(0, input.limit)
      .flatMap((e) => {
        try {
          return [runSummary(ctx.workspace.get(e.id))];
        } catch {
          return [];
        }
      }),
});

defineOperation({
  name: "run_note.add",
  title: "Note on the run",
  description: "The operator writes down something about how the agents did: what they missed (kind missed), or any other observation (kind note).",
  kind: "write",
  actors: ["human"],
  input: z.object({ engagementId, kind: z.enum(["missed", "note"]), text: z.string().min(1).max(1000) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const note = addRunNote(e, input.kind, input.text, ctx.caller.actor);
    e.audit(ctx.caller.actor, "run_note.add", { note: note.id }, note);
    e.emit({ type: "metrics.changed" });
    return note;
  },
});

defineOperation({
  name: "run_note.remove",
  title: "Remove a note on the run",
  description: "Removes a note about how the agents did.",
  kind: "write",
  actors: ["human"],
  input: z.object({ engagementId, id: z.string() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    removeRunNote(e, input.id);
    e.audit(ctx.caller.actor, "run_note.remove", { note: input.id }, {});
    e.emit({ type: "metrics.changed" });
    return { status: "removed" };
  },
});
