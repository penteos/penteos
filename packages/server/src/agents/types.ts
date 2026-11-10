import type { Language } from "@penteos/core";
import type { Caller, OperationContext } from "@penteos/core";

/** What the agent sidebar renders. Every provider translates its own stream into these. */
export type AgentEvent =
  | { kind: "user"; text: string; at: string; auto?: boolean; by?: string }
  | { kind: "notice"; text: string }
  | { kind: "delta"; text: string }
  | { kind: "text"; text: string }
  | { kind: "tool"; id: string; name: string; input: unknown; status: "running" | "ok" | "error"; summary?: string; approvalId?: string; runId?: string }
  | { kind: "status"; text: string }
  | { kind: "error"; text: string }
  /** A card in the Sala: what the verifier has to say, never a chat message. */
  | { kind: "card"; card: SalaCard }
  | { kind: "done"; provider: ProviderId; at: string };

export interface SalaCard {
  type: "verdict";
  title: string;
  text: string;
  at: string;
  /** Who it is about: the verifier's transcript key, a finding. */
  key?: string;
  findingId?: string;
  who?: string;
}

/** Built-in providers, or a plugin's (`plugin:<pluginId>:<id>`), always remote: always masked. */
export type ProviderId = "chatgpt" | "claude-code" | "codex" | "claude-api" | "openai-api" | "deepseek" | "local" | `plugin:${string}`;

export interface ProviderSettings {
  apiKey?: string;
  model?: string;
  baseUrl?: string;
}

export interface TurnContext {
  /** System prompt describing the engagement and the rules of the game. */
  system: string;
  /** Operation context the agent acts with (its own identity, policy and audit trail). */
  ops: OperationContext;
  caller: Caller;
  settings: ProviderSettings;
  /** Where CLI agents run, and how they reach the core over MCP. */
  workDir: string;
  dataDir: string;
  emit(event: AgentEvent): void;
  signal: AbortSignal;
  /** Language for what this turn shows a person (status and error lines). */
  lang?: Language;
  /** Operations this agent may use (all agent operations when absent). */
  allow?: (operation: string) => boolean;
}

/** One conversation with one provider. Keeps the provider-specific history. */
export interface ProviderSession {
  send(text: string, ctx: TurnContext): Promise<void>;
  /** Serializable state, so the conversation survives a restart. */
  snapshot(): unknown;
}

/**
 * Folds a streamed piece of text into a transcript. A notice or status that arrived while the agent
 * was writing does not cut its message in two: the text keeps growing in place.
 */
export function foldDelta(events: AgentEvent[], text: string): void {
  for (let i = events.length - 1; i >= 0; i--) {
    const e = events[i]!;
    if (e.kind === "text") {
      e.text += text;
      return;
    }
    if (e.kind !== "notice" && e.kind !== "status") break;
  }
  events.push({ kind: "text", text });
}
