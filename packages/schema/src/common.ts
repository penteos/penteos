import { z } from "zod";

/** Crockford base32 ULID: 10 chars of time + 16 chars of randomness. */
export const Ulid = z.string().regex(/^[0-9A-HJKMNP-TV-Z]{26}$/, "must be a ULID");
export type Ulid = z.infer<typeof Ulid>;

/** UTC timestamp, always with a trailing Z. */
export const IsoDate = z.iso.datetime();
export type IsoDate = z.infer<typeof IsoDate>;

/** Content address of a raw artifact. */
export const Sha256Ref = z.string().regex(/^sha256:[0-9a-f]{64}$/, "must be sha256:<64 hex chars>");
export type Sha256Ref = z.infer<typeof Sha256Ref>;

/**
 * How much a target-facing action can affect the target, ordered from least to most.
 *.
 */
export const RISK_LEVELS = ["passive", "active", "intrusive", "exploitation"] as const;
export const RiskLevel = z.enum(RISK_LEVELS);
export type RiskLevel = z.infer<typeof RiskLevel>;

export function riskRank(risk: RiskLevel): number {
  return RISK_LEVELS.indexOf(risk);
}

/** True when `risk` is strictly above `ceiling`. */
export function riskExceeds(risk: RiskLevel, ceiling: RiskLevel): boolean {
  return riskRank(risk) > riskRank(ceiling);
}

export const Severity = z.enum(["critical", "high", "medium", "low", "info"]);
export type Severity = z.infer<typeof Severity>;

/** Who did something. Humans and agents are both first-class actors. */
export const Actor = z.discriminatedUnion("type", [
  z.object({ type: z.literal("human"), id: Ulid }),
  z.object({ type: z.literal("agent"), id: Ulid }),
  z.object({ type: z.literal("parser"), id: z.string().min(1) }),
  z.object({ type: z.literal("system"), id: z.string().min(1) }),
]);
export type Actor = z.infer<typeof Actor>;

export const Markdown = z.string();
