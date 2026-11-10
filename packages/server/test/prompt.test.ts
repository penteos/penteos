import { expect, it } from "vitest";
import { systemPrompt } from "../src/agents/tools.js";
import { languageRules, type EngagementInfo, type ScopeRule } from "@penteos/core";

/** Autonomy changes the interruption cadence, never the limits - and maestro (interactive) stays untouched. */

const base = { id: "e", name: "X", clientName: "C", mode: "web", roundMode: "pentest", status: "active", maxRisk: "active", dataPolicy: "any_provider", autonomy: "maestro", scope: [] as ScopeRule[] } as unknown as EngagementInfo & { scope: ScopeRule[] };

it("maestro auto adds the autopilot guidance without loosening any limit; maestro adds nothing", () => {
  const maestro = systemPrompt({ ...base, autonomy: "maestro" }, "tools");
  const auto = systemPrompt({ ...base, autonomy: "maestro_auto" }, "tools");
  // Plain maestro is the baseline: no autopilot section at all.
  expect(maestro).not.toMatch(/AUTO \(autopilot\)/);
  // Auto states the behaviour AND the invariants (does not loosen anything).
  expect(auto).toMatch(/AUTO \(autopilot\)/);
  expect(auto).toMatch(/does not loosen any limit/);
  expect(auto).toMatch(/never (widen|widens)? ?the scope/i);
  // The risk ceiling shown is identical in both: auto never changes it.
  expect(auto).toContain("Maximum risk allowed: active");
  expect(maestro).toContain("Maximum risk allowed: active");
});

it("copilot states that the operator executes each action", () => {
  const copilot = systemPrompt({ ...base, autonomy: "copilot" }, "tools");
  expect(copilot).toMatch(/COPILOT/);
  expect(copilot).toMatch(/pending_approval/);
});

it("the chat follows the language the operator writes in; the deliverable keeps its own", () => {
  for (const ui of ["en", "es"] as const) {
    const prompt = systemPrompt({ ...base, language: "en" } as typeof base, "tools", ui);
    // The interface language is only the default for the conversation…
    expect(prompt).toMatch(/by default/);
    // …the operator's latest message decides, and that never moves the deliverable.
    expect(prompt).toMatch(/answer in the language of their latest message/);
    expect(prompt).toMatch(/never changes the deliverable's language/);
    expect(prompt).toMatch(/Write everything that ends up in the deliverable in English/);
  }
});

it("the agent is told never to write long dashes, in the chat or the deliverable", () => {
  for (const [op, proj] of [["en", "en"], ["es", "en"], [null, "es"]] as const) {
    const rules = languageRules(op, proj);
    expect(rules).toMatch(/Never write the long dash/);
    expect(rules).not.toMatch(/[\u2014\u2013]/);
  }
});
