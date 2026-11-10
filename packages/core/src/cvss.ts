import cvssLib from "ae-cvss-calculator";

/**
 * CVSS 4.0 and 3.1 scores, computed with the FIRST algorithms (metæffekt's implementation:
 * CVSS 4.0 needs the official macrovector table, which is not something to retype by hand).
 */

// The package is CommonJS: its classes hang from the default export.
const lib = ((cvssLib as unknown as { CvssCalculator?: unknown }).CvssCalculator ?? cvssLib) as {
  Cvss4P0: new (v: string) => { calculateScores(): { base: number; overall: number } };
  Cvss3P1: new (v: string) => { calculateScores(): { base: number; overall: number } };
};

export interface CvssScore {
  version: "4.0" | "3.1";
  vector: string;
  score: number;
  severity: "info" | "low" | "medium" | "high" | "critical";
}

export function severityFor(score: number): CvssScore["severity"] {
  if (score === 0) return "info";
  if (score < 4) return "low";
  if (score < 7) return "medium";
  if (score < 9) return "high";
  return "critical";
}

export function scoreCvss(vector: string): CvssScore {
  const v = vector.trim();
  if (v.startsWith("CVSS:4.0/")) {
    const score = new lib.Cvss4P0(v).calculateScores().overall;
    return { version: "4.0", vector: v, score, severity: severityFor(score) };
  }
  if (v.startsWith("CVSS:3.1/")) {
    const score = new lib.Cvss3P1(v).calculateScores().overall;
    return { version: "3.1", vector: v, score, severity: severityFor(score) };
  }
  throw new Error('the vector must start with "CVSS:4.0/" or "CVSS:3.1/"');
}
