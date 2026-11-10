import { defineOperation } from "../registry.js";
import { z } from "zod";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "audit.query",
  title: "Audit log",
  description: "Most recent audit events (who did what, when).",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, limit: z.number().int().min(1).max(1000).default(100), beforeSeq: z.number().int().optional() }),
  handler: (input, ctx) =>
    ctx.engagement(input.engagementId).auditEvents({ limit: input.limit, ...(input.beforeSeq ? { beforeSeq: input.beforeSeq } : {}) }),
});

defineOperation({
  name: "audit.verify",
  title: "Verify audit chain",
  description: "Recomputes the audit hash chain and reports whether it was tampered with.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => ctx.engagement(input.engagementId).verifyAudit(),
});
