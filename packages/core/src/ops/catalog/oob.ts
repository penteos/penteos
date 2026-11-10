import { z } from "zod";
import { isPublicServer, oobDisable, oobEnable, oobNew, oobState, PUBLIC_OOB_SERVERS } from "../../oob.js";
import { defineOperation, OperationError } from "../registry.js";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// Out-of-band interactions: proof for blind vulnerabilities, where
// the target contacts a server of ours instead of answering. One host per test; each contact is
// recorded with the raw request and the agent that asked hears it as news.

const PUBLIC_NOTE = `This is a PUBLIC interaction server (${PUBLIC_OOB_SERVERS.join(", ")}): whatever the target sends it reaches a third party. Fine for labs; for a real engagement run your own with oob_enable(server: "your.server", tokenSecret: ...).`;

defineOperation({
  name: "oob.new",
  title: "Get an out-of-band test host",
  description:
    "Returns a unique host for an out-of-band test (SSRF, blind XXE, blind command or SQL injection, blind SSTI): put the returned address in your payload (as a URL, a hostname to resolve, an external entity…). If the target contacts it, the interaction is recorded as evidence and you hear it as news - that is proof the input reached a sink. State the purpose concretely; it is auto-enabled with the project's interaction server if it was off.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    purpose: z.string().min(1).max(300).describe('What you are testing: e.g. "SSRF in the url field of POST /api/import"'),
    target: z.string().max(300).optional().describe("The endpoint or parameter under test, for the record"),
  }),
  handler: async (input, ctx) => {
    try {
      const r = await oobNew(ctx.engagement(input.engagementId), { purpose: input.purpose, ...(input.target ? { target: input.target } : {}), by: ctx.caller.actor });
      return {
        status: "ready",
        address: r.address,
        httpUrl: `http://${r.address}`,
        tag: r.tag,
        note: `Put ${r.address} in your payload (or http://${r.address}). A DNS lookup or HTTP request to it from the target proves the input reached a sink; check with oob_check and cite the interaction's rawId as evidence.${r.public ? ` ${PUBLIC_NOTE}` : ""}`,
      };
    } catch (e) {
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
  },
});

defineOperation({
  name: "oob.check",
  title: "Out-of-band interactions",
  description: "The interactions the out-of-band server received (the target contacting us), newest first. Filter by the tag oob_new returned to see only one test's. Each carries the protocol, the source address and a rawId to cite as evidence.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, tag: z.string().optional(), limit: z.number().int().min(1).max(500).default(100) }),
  handler: (input, ctx) => {
    const s = oobState(ctx.engagement(input.engagementId));
    const list = s.interactions.filter((i) => !input.tag || i.tag === input.tag).slice(-input.limit).reverse();
    return { enabled: s.enabled, server: s.server, base: s.base ?? null, count: list.length, interactions: list };
  },
});

defineOperation({
  name: "oob.enable",
  title: "Set up the out-of-band server",
  description: `Turns on out-of-band testing and chooses the interaction server. Default is a public server (${PUBLIC_OOB_SERVERS[0]}), good for labs. For a real engagement run your own interactsh server and pass its host and, if it needs one, the name of a saved secret with its token, so nothing the target sends reaches a third party.`,
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, server: z.string().min(1).max(200).optional(), tokenSecret: z.string().max(100).optional() }),
  handler: async (input, ctx) => {
    try {
      const r = await oobEnable(ctx.engagement(input.engagementId), { ...(input.server ? { server: input.server } : {}), ...(input.tokenSecret ? { tokenSecret: input.tokenSecret } : {}) });
      return { status: "enabled", server: r.server, base: r.base, note: r.public ? PUBLIC_NOTE : "Using your own interaction server: nothing reaches a third party." };
    } catch (e) {
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
  },
});

defineOperation({
  name: "oob.disable",
  title: "Stop the out-of-band server",
  description: "Stops the out-of-band listener. Pending tests stop being watched.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    oobDisable(ctx.engagement(input.engagementId));
    return { status: "disabled" };
  },
});
