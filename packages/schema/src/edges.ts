import { z } from "zod";
import { IsoDate, Ulid } from "./common.js";
import { EntityRef, type EntityKind } from "./entities.js";

/** Typed relations of the v0 graph. */
export const EDGE_CATALOG = {
  resolves_to: { from: ["domain"], to: ["host"] },
  alias_of: { from: ["domain"], to: ["domain"] },
  runs_on: { from: ["service"], to: ["host"] },
  served_by: { from: ["webapp"], to: ["service"] },
  hosted_at: { from: ["webapp"], to: ["domain"] },
  belongs_to: { from: ["endpoint"], to: ["webapp"] },
  member_of: { from: ["principal"], to: ["principal"] },
  // In Active Directory the target is often a computer account (BloodHound) rather than a host.
  admin_to: { from: ["principal"], to: ["host", "principal"] },
  has_session: { from: ["principal"], to: ["host", "principal"] },
  authenticates: { from: ["credential"], to: ["principal"] },
  valid_on: { from: ["credential"], to: ["service", "webapp"] },
  cracked_from: { from: ["credential"], to: ["credential"] },
  related_to: { from: "*", to: "*" },
} as const satisfies Record<string, { from: readonly EntityKind[] | "*"; to: readonly EntityKind[] | "*" }>;

export type EdgeType = keyof typeof EDGE_CATALOG;
export const EdgeType = z.enum(Object.keys(EDGE_CATALOG) as [EdgeType, ...EdgeType[]]);

function allows(side: readonly EntityKind[] | "*", kind: EntityKind): boolean {
  return side === "*" || side.includes(kind);
}

export function isEdgeAllowed(type: EdgeType, from: EntityKind, to: EntityKind): boolean {
  const spec = EDGE_CATALOG[type];
  return allows(spec.from, from) && allows(spec.to, to);
}

export const Edge = z.object({
  id: Ulid,
  engagementId: Ulid,
  type: EdgeType,
  from: EntityRef,
  to: EntityRef,
  attributes: z.record(z.string(), z.unknown()).optional(),
  firstSeen: IsoDate,
  lastSeen: IsoDate,
  deletedAt: IsoDate.optional(),
});
export type Edge = z.infer<typeof Edge>;
