import type { Caller } from "@penteos/core";

/** The local operator (solo mode). In team mode each operator gets their own identity. */
export const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };

/** External agents connected over MCP with the agent token. */
export const AGENT: Caller = {
  actor: { type: "agent", id: "01JA0000000000000000AGENT1" },
  policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" },
};

/** The built-in Maestro: autonomous within "active" risk; anything above needs human approval. */
export const MAESTRO: Caller = {
  actor: { type: "agent", id: "01JA000000000000000000MSTR" },
  policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" },
};
