import { z } from "zod";
import { DEFAULT_PACE, PACE_LIMITS, type Pace, PACES, paceStats } from "../../pacing.js";
import { defineOperation, paceOf } from "../registry.js";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// How fast Penteos talks to the targets (pacing.ts): the project's pace and what each host got.

const pace = z.enum(PACES as [Pace, ...Pace[]]);

defineOperation({
  name: "pacing.get",
  title: "Pace towards the targets",
  description:
    "How fast Penteos talks to this project's targets: the pace (quiet 2 req/s per host, normal 5, aggressive 20, off for labs), and per host how many requests went, how long they waited for their turn, how many answers asked to slow down (429/503) and whether the host is paused now. Penteos's own requests wait for their turn automatically and external tools get matching rate options; a 429 or 503 pauses the host by itself.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    const current = paceOf(ctx.engagement(input.engagementId));
    return { pace: current, default: DEFAULT_PACE, ...(current === "off" ? {} : { limits: PACE_LIMITS[current] }), hosts: paceStats() };
  },
});

defineOperation({
  name: "pacing.set",
  title: "Set the pace towards the targets",
  description: "quiet: a fragile production system or one with tight rate limits; normal (default): a client's production site; aggressive: a staging copy or a target that can take it; off: a lab only, no limit at all.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ engagementId, pace }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    e.setMeta("pacing.pace", input.pace, ctx.caller.actor);
    return { pace: input.pace, ...(input.pace === "off" ? {} : { limits: PACE_LIMITS[input.pace] }) };
  },
});
