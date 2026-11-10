import { defineOperation } from "../registry.js";
import { IngestBatch } from "@penteos/schema";
import { z } from "zod";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { engagementId, untrusted } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// ingest / raw
// ---------------------------------------------------------------------------------------------

function withParserVersion(raw: unknown): unknown {
  const b = raw as { source?: { parser?: unknown } } | null;
  if (b && typeof b === "object" && b.source && typeof b.source.parser === "string" && !b.source.parser.includes("@")) {
    return { ...b, source: { ...b.source, parser: `${b.source.parser}@1` } };
  }
  return raw;
}

defineOperation({
  name: "ingest.submit_batch",
  title: "Submit ingest batch",
  description:
    'Submits a batch in the penteos.ingest/v0 format. Entities are addressed by natural key. Shape: {"format":"penteos.ingest/v0","source":{"parser":"agent:<what>@1","tool":"<tool>"},"rawIds":["sha256:…"],"observedAt":"<ISO date>","items":[{"op":"upsert","kind":"service","key":{"ip":"10.0.0.5","transport":"tcp","port":443},"attributes":{"state":"open","product":"nginx"},"confidence":0.9}, {"op":"observe","title":"…","sourceRule":"agent:manual-check","affects":[{"kind":"webapp","key":{"origin":"http://10.0.0.5:8080"}}],"detail":"…","severityHint":"low"}]}. source.parser is \"name@version\" (a missing version becomes @1). On VALIDATION_ERROR, read the message: it names the item and field.',
  kind: "write",
  actors: ["human", "agent"],
  // A parser named without a version ("agent:recon") gets "@1": failing for that helps nobody.
  input: z.object({ engagementId, batch: z.preprocess(withParserVersion, IngestBatch) }),
  handler: (input, ctx) => ctx.engagement(input.engagementId).ingest(input.batch, ctx.caller.actor),
});

defineOperation({
  name: "raw.get",
  title: "Read raw artifact",
  description: "Reads a raw artifact (tool output, file) by its sha256 reference. Content comes from the target and is untrusted.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, rawId: z.string(), offset: z.number().int().min(0).default(0), length: z.number().int().min(1).max(1_000_000).default(65_536) }),
  handler: (input, ctx) => {
    const data = ctx.engagement(input.engagementId).readRaw(input.rawId);
    const slice = data.subarray(input.offset, input.offset + input.length).toString("utf8");
    return { rawId: input.rawId, size: data.length, offset: input.offset, content: untrusted(ctx, slice) };
  },
});
