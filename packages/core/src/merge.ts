import { type Actor, type EntityKind, fieldClass } from "@penteos/schema";
import { canonicalJson } from "./store/hash.js";

/**
 * Computes the current state of an entity from its sightings.
 * Pure function: the stored state can always be recomputed from the sightings.
 */

export interface SightingInput {
  attributes: Record<string, unknown>;
  source: Actor;
  confidence: number;
  observedAt: string;
}

export interface FieldConflict {
  field: string;
  values: Array<{ value: unknown; source: Actor; observedAt: string }>;
}

export interface MergeResult {
  attributes: Record<string, unknown>;
  conflicts: FieldConflict[];
}

const CONFLICT_CONFIDENCE = 0.7;
const DESCRIPTIVE_WINDOW_MS = 24 * 60 * 60 * 1000;

function sourceKey(actor: Actor): string {
  return `${actor.type}:${actor.id}`;
}

function newer(a: SightingInput, b: SightingInput): boolean {
  if (a.observedAt !== b.observedAt) return a.observedAt > b.observedAt;
  return a.confidence > b.confidence;
}

export function mergeSightings(
  kind: EntityKind,
  sightings: SightingInput[],
  humanFields: Record<string, unknown> = {},
): MergeResult {
  const fields = new Set(sightings.flatMap((s) => Object.keys(s.attributes)));
  const attributes: Record<string, unknown> = {};
  const conflicts: FieldConflict[] = [];

  for (const field of fields) {
    const withField = sightings.filter((s) => s.attributes[field] !== undefined);
    const values = withField.map((s) => s.attributes[field]);

    // Lists: union of everything ever seen.
    if (values.every(Array.isArray)) {
      const seen = new Map<string, unknown>();
      for (const v of values.flat()) seen.set(canonicalJson(v), v);
      attributes[field] = [...seen.values()];
      continue;
    }

    // Scalars: most recent observation wins, ties broken by confidence.
    let winner = withField[0]!;
    for (const s of withField) if (newer(s, winner)) winner = s;
    attributes[field] = winner.attributes[field];

    const cls = fieldClass(kind, field);
    if (cls === "volatile") continue;

    // Latest value reported by each source.
    const latestBySource = new Map<string, SightingInput>();
    for (const s of withField) {
      const key = sourceKey(s.source);
      const current = latestBySource.get(key);
      if (!current || newer(s, current)) latestBySource.set(key, s);
    }
    let candidates = [...latestBySource.values()];
    if (cls === "descriptive") {
      const cutoff = Date.parse(winner.observedAt) - DESCRIPTIVE_WINDOW_MS;
      candidates = candidates.filter(
        (s) => s.confidence >= CONFLICT_CONFIDENCE && Date.parse(s.observedAt) >= cutoff,
      );
    }
    const distinct = new Set(candidates.map((s) => canonicalJson(s.attributes[field])));
    if (distinct.size > 1) {
      conflicts.push({
        field,
        values: candidates.map((s) => ({ value: s.attributes[field], source: s.source, observedAt: s.observedAt })),
      });
    }
  }

  // A human decision beats every automatic source and settles any conflict on that field.
  for (const [field, value] of Object.entries(humanFields)) {
    attributes[field] = value;
  }
  return { attributes, conflicts: conflicts.filter((c) => !(c.field in humanFields)) };
}
