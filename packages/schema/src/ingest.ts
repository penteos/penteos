import { z } from "zod";
import { IsoDate, Severity, Sha256Ref, Ulid } from "./common.js";
import { EdgeType } from "./edges.js";
import { CredentialType, EntityKind } from "./entities.js";

/**
 * The common ingest format. Every parser - official, community or
 * AI extraction - emits batches in this format. This is a public contract: breaking changes
 * require a new `format` version.
 */

export const INGEST_FORMAT = "penteos.ingest/v0" as const;

const KeyFields = z.record(z.string(), z.union([z.string(), z.number()]));

export const KeyRef = z.object({ kind: EntityKind, key: KeyFields });
export type KeyRef = z.infer<typeof KeyRef>;

const Confidence = z.number().min(0).max(1);
const Attributes = z.record(z.string(), z.unknown());

export const IngestItem = z.discriminatedUnion("op", [
  z.object({
    op: z.literal("upsert"),
    kind: EntityKind,
    key: KeyFields,
    attributes: Attributes.optional(),
    confidence: Confidence.optional(),
  }),
  z.object({
    op: z.literal("relate"),
    type: EdgeType,
    from: KeyRef,
    to: KeyRef,
    attributes: Attributes.optional(),
    confidence: Confidence.optional(),
  }),
  z.object({
    op: z.literal("observe"),
    title: z.string().min(1),
    sourceRule: z.string().min(1),
    affects: z.array(KeyRef).min(1),
    location: z.string().optional(),
    severityHint: Severity.optional(),
    detail: z.string().optional(),
    /** The raw output that shows it (a response body), for evidence and for deepening. */
    rawId: z.string().optional(),
  }),
  z.object({
    op: z.literal("credential"),
    credentialType: CredentialType,
    /** Moved to the vault and stripped from the batch before it is persisted. */
    secret: z.string().min(1),
    principal: KeyRef.optional(),
    validOn: z.array(KeyRef).optional(),
    source: z.string().optional(),
  }),
  z.object({ op: z.literal("http"), rawId: Sha256Ref, endpoint: KeyRef }),
  z.object({ op: z.literal("note"), body: z.string().min(1), mentions: z.array(KeyRef).optional() }),
]);
export type IngestItem = z.infer<typeof IngestItem>;

export const IngestBatch = z.object({
  format: z.literal(INGEST_FORMAT),
  source: z.object({
    parser: z.string().regex(/^[a-z0-9:_-]+@[\w.+-]+$/, 'must look like "name@version"'),
    tool: z.string().optional(),
    toolVersion: z.string().optional(),
  }),
  runId: Ulid.optional(),
  rawIds: z.array(Sha256Ref),
  networkContext: z.string().optional(),
  observedAt: IsoDate,
  items: z.array(IngestItem),
});
export type IngestBatch = z.infer<typeof IngestBatch>;
