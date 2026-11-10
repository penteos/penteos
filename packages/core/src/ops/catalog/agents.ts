import { defineOperation, OperationError, type OperationContext } from "../registry.js";
import { z } from "zod";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// Agent runtime controls: the Team panel and the panic button
// ---------------------------------------------------------------------------------------------

function agentsOf(ctx: OperationContext) {
  if (!ctx.agents) throw new OperationError("VALIDATION_ERROR", "the agents run with the desktop app or the team server");
  return ctx.agents;
}

defineOperation({
  name: "team.status",
  title: "Team status",
  description: "Every agent of the project and its state: the Maestro, the verifier and whether the agents are paused.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => agentsOf(ctx).teamStatus(ctx.engagement(input.engagementId).info.id),
});

for (const action of ["pause", "resume"] as const) {
  defineOperation({
    name: `agents.${action}`,
    title: action === "pause" ? "Pause every agent" : "Resume the agents",
    description:
      action === "pause"
        ? "The panic button: pauses the Maestro and the verifier of the project. Humans keep working (unlike stop-work)."
        : "Resumes the agents after a pause.",
    kind: "admin",
    actors: ["human"],
    input: z.object({ engagementId }),
    handler: (input, ctx) => {
      const e = ctx.engagement(input.engagementId);
      if (action === "pause") agentsOf(ctx).pauseAll(e.info.id, ctx.caller);
      else agentsOf(ctx).resumeAll(e.info.id, ctx.caller);
      return { paused: action === "pause" };
    },
  });
}
