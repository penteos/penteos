import { defineOperation, OperationError } from "../registry.js";
import { z } from "zod";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// Secrets (credentials, tokens, session cookies) - used by reference

defineOperation({
  name: "secret.save",
  title: "Save a credential or session",
  description:
    "Saves a password, token, API key or session cookie in the engagement. From then on use it as {{secret:name}} inside commands (Penteos substitutes it only when running); its value is hidden from commands, logs, outputs you read and the conversation. Save credentials as soon as you obtain them, and never write their values in messages or findings.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    name: z.string().min(1).max(60).describe("Short name, e.g. dvwa_admin or dvwa_session"),
    kind: z.enum(["password", "token", "cookie", "api_key", "key", "other"]),
    value: z.string().min(1),
    note: z.string().optional().describe("What it is for: user, application, how it was obtained"),
  }),
  handler: (input, ctx) => ctx.engagement(input.engagementId).saveSecret(input, ctx.caller.actor),
});

defineOperation({
  name: "secret.list",
  title: "Credentials and sessions",
  description: "The saved credentials and sessions, by name and reference (never their values).",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => ctx.engagement(input.engagementId).secrets(),
});

defineOperation({
  name: "secret.reveal",
  title: "Reveal a credential",
  description: "Shows the value of a saved credential (humans only; recorded in the audit).",
  kind: "target",
  actors: ["human"],
  input: z.object({ engagementId, name: z.string() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const value = e.secretValue(input.name);
    if (value === undefined) throw new OperationError("NOT_FOUND", `secret ${input.name} not found`);
    e.audit(ctx.caller.actor, "secret.reveal", { secret: input.name }, { name: input.name });
    return { name: input.name, value };
  },
});

defineOperation({
  name: "secret.delete",
  title: "Delete a credential",
  description: "Deletes a saved credential or session.",
  kind: "target",
  actors: ["human"],
  input: z.object({ engagementId, name: z.string() }),
  handler: (input, ctx) => {
    ctx.engagement(input.engagementId).deleteSecret(input.name, ctx.caller.actor);
    return { status: "deleted" };
  },
});
