import { z } from "zod";
import { privacyReport, resetPrivacyMeter } from "../../privacy/meter.js";
import { maskedCounts, privacyLevel, setPrivacyLevel } from "../../privacy/model.js";
import { vaultSize } from "../../privacy/vault.js";
import { classifyFields, FIELD_KINDS, fieldClassification } from "../../privacy/mask.js";
import { defineOperation } from "../registry.js";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// The leak meter: what reached the models from this project.

defineOperation({
  name: "privacy.report",
  title: "What reached the model",
  description: "How much text went from this project to the AI models, how many planted canaries reached them, and how many sensitive values the detectors recognised in what was sent (by type).",
  kind: "read",
  actors: ["human"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    return { level: privacyLevel(e), masked: maskedCounts(e), vault: vaultSize(e), ...privacyReport(e) };
  },
});

defineOperation({
  name: "privacy.set_level",
  title: "Data privacy towards the model",
  description: "standard: the client's personal and financial data and secrets reach the models only as markers (the real values stay here and go back in on the way to the target). off: the models see the data as it comes (labs).",
  kind: "write",
  actors: ["human"],
  input: z.object({ engagementId, level: z.enum(["standard", "off"]) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    setPrivacyLevel(e, input.level);
    e.audit(ctx.caller.actor, "privacy.set_level", {}, { level: input.level });
    e.emit({ type: "metrics.changed" });
    return { level: input.level };
  },
});

defineOperation({
  name: "privacy.reset",
  title: "Reset the leak meter",
  description: "Starts the leak meter of this project from zero (to measure a new run).",
  kind: "write",
  actors: ["human"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    resetPrivacyMeter(e);
    e.audit(ctx.caller.actor, "privacy.reset", {}, {});
    e.emit({ type: "metrics.changed" });
    return privacyReport(e);
  },
});

defineOperation({
  name: "privacy.fields",
  title: "Field names to classify",
  description: "This application's field names that Penteos did not recognise as personal or not (only the names, never their values), and the ones already classified. Classify the pending ones with privacy_classify_fields.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => fieldClassification(ctx.engagement(input.engagementId)),
});

defineOperation({
  name: "privacy.classify_fields",
  title: "Classify field names",
  description:
    "Says which of this application's fields hold personal data, from their names alone: name (a person), email, phone, doc (an identity document), ar_cuit, address, birthdate, bank, card, content (free text about a person: notes, records), secret (tokens, passwords) or none. Their values reach you masked from then on. When unsure whether a field holds a person's data, choose the personal kind.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, fields: z.array(z.object({ name: z.string().min(1).max(80), kind: z.enum(FIELD_KINDS) })).min(1).max(500) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const total = classifyFields(e, input.fields);
    e.audit(ctx.caller.actor, "privacy.classify_fields", {}, { count: input.fields.length });
    return { status: "classified", classified: total };
  },
});
