/**
 * The Maestro's memory over a long round. The providers that run the loop in Penteos (an
 * OpenAI-compatible API, Claude by API, the ChatGPT plan) send the whole conversation on every
 * step; left alone it grows until the model refuses it and the round stops. This keeps it within a
 * budget, in two steps:
 *
 *  1. Old tool results (outside the most recent ones) are cut to their beginning, with a note that
 *     the data is still in Penteos. No model call: most of a long conversation is tool output.
 *  2. If that is not enough, the older part of the conversation is summed up by the same model into
 *     a structured memory (the operator's instructions, what was done, findings with their ids,
 *     open leads, pending decisions, what not to repeat), and replaced by it. The recent tail stays
 *     as it was and always starts where the API accepts it (a call is never parted from its result).
 *
 * A summary that fails never stops the round: the older part is dropped with a note that sends the
 * model back to Penteos's own record (engagement.brief, the findings, the board).
 *
 * It works on any of the three formats through an adapter, so the rules are written once.
 */

import type { AgentEvent } from "./types.js";
import { msg } from "./messages.js";
import type { Language } from "@penteos/core";

/** Characters per token, on the safe side for JSON-heavy text (estimates, not billing). */
const CHARS_PER_TOKEN = 3.5;
/** Tool results kept whole, counted from the end. */
const KEEP_RECENT_RESULTS = 16;
/** A result longer than this, outside the recent ones, is cut. */
const TRIM_OVER = 900;
/** What remains of a cut result. */
const TRIM_TO = 450;
/** Share of the budget at which old results are cut, and at which the older part is summed up. */
const PRUNE_AT = 0.6;
const SUMMARIZE_AT = 0.85;
/** Share of the budget the untouched recent tail may take after a summary. */
const TAIL_SHARE = 0.3;
/** What the model reading the transcript gets of each message, at most. */
const RENDER_EACH = 2400;
const RENDER_TOTAL = 240_000;

/** The default budget: generous for hosted models, small for local ones (their windows are small). */
export function memoryBudget(local: boolean): number {
  const fromEnv = Number(process.env.PENTEOS_MEMORY_TOKENS);
  if (Number.isFinite(fromEnv) && fromEnv >= 8000) return fromEnv;
  return local ? 24_000 : 120_000;
}

export const MEMORY_HEADER = "[Memory of the earlier part of this round, written when the conversation was compacted]";

export const TRIM_NOTE = "[cut to save memory: the full result is still in Penteos; query it again if you need it]";

/** The instructions for the summary call. */
export const SUMMARY_SYSTEM = `You are compacting the working memory of the Maestro, an AI agent running an authorized penetration test inside Penteos. Below is the older part of its conversation (the operator's messages, its own messages, the tools it called and their results, and possibly an earlier memory). Write the memory it will work from from now on. It replaces that part entirely, so anything you leave out is lost to it.

Write it in English, as compact notes, under these headings:
1. Operator instructions: every instruction, restriction, preference and answer from the operator or the client, verbatim when short.
2. Engagement state: phase, scope facts that matter, accounts and identities in use (never secret values; keep markers such as «secret:2» as they are).
3. Done: what was tested, against what, with which result. Group by target and technique. Include negative results ("tested X on /path: not vulnerable, because …").
4. Findings: every finding with its id, title, severity, status and evidence ids.
5. Open leads: what looked promising and was not finished, with the exact endpoints, parameters and ids needed to resume.
6. Pending: approvals or answers being waited for, runs still going (with their ids).
7. Do not repeat: approaches that failed or were refused, and why.

Keep every id (entity, finding, run, approval, evidence), endpoint, parameter name and marker («email:3») exactly as written. Do not invent anything that is not in the transcript. Do not address anyone; just write the notes.`;

export interface MemoryAdapter<M> {
  /** Messages at the start that are never touched (a system message). */
  pinned(messages: M[]): number;
  /** Characters this message costs. */
  size(m: M): number;
  /** Text of a tool result, or undefined when this is not one. */
  resultText(m: M): string | undefined;
  /** The same tool result with another text. */
  withResultText(m: M, text: string): M;
  /** Whether a kept tail may start at index i (the API accepts the history from there). */
  canStartTail(messages: M[], i: number): boolean;
  /** One line or block of readable transcript. */
  render(m: M): string;
  /** The message(s) that carry the memory, placed where the older part was. */
  memory(text: string): M[];
}

export interface MemoryOutcome {
  /** Old results were cut. */
  trimmed: number;
  /** The older part was summed up (or dropped, when the summary failed). */
  summarized: boolean;
  summaryFailed?: boolean;
  beforeTokens: number;
  afterTokens: number;
  /** The budget it worked to: lower than asked after an overflow (the model's window is smaller). */
  budgetTokens: number;
}

export function estimateTokens<M>(messages: M[], a: MemoryAdapter<M>): number {
  let chars = 0;
  for (const m of messages) chars += a.size(m);
  return Math.ceil(chars / CHARS_PER_TOKEN);
}

/**
 * Keeps the conversation within the budget, in place. `force` compacts even under the thresholds
 * (the model already said the context is too long). Returns what was done, or undefined when
 * nothing had to change. A turn stopped by the operator during the summary leaves it untouched.
 */
export async function keepWithinBudget<M>(
  messages: M[],
  a: MemoryAdapter<M>,
  budgetTokens: number,
  summarize: (system: string, transcript: string) => Promise<string>,
  options: { force?: boolean; signal?: AbortSignal } = {},
): Promise<MemoryOutcome | undefined> {
  const force = options.force ?? false;
  const before = estimateTokens(messages, a);
  // The model refused what was sent: its window is smaller than assumed. Work to half of it.
  if (force) budgetTokens = Math.min(budgetTokens, Math.max(4000, Math.floor(before * 0.5)));
  if (!force && before <= budgetTokens * PRUNE_AT) return undefined;

  // 1. Cut old tool results.
  let trimmed = 0;
  const resultIdx: number[] = [];
  for (let i = a.pinned(messages); i < messages.length; i++) if (a.resultText(messages[i]!) !== undefined) resultIdx.push(i);
  for (const i of resultIdx.slice(0, Math.max(0, resultIdx.length - KEEP_RECENT_RESULTS))) {
    const text = a.resultText(messages[i]!)!;
    if (text.length <= TRIM_OVER || text.endsWith(TRIM_NOTE)) continue;
    messages[i] = a.withResultText(messages[i]!, `${text.slice(0, TRIM_TO)}… ${TRIM_NOTE}`);
    trimmed++;
  }
  const afterTrim = estimateTokens(messages, a);
  if (!force && afterTrim <= budgetTokens * SUMMARIZE_AT) return { trimmed, summarized: false, beforeTokens: before, afterTokens: afterTrim, budgetTokens };

  // 2. Sum up the older part: keep a recent tail that starts where the API accepts it.
  const head = a.pinned(messages);
  const tailBudget = budgetTokens * TAIL_SHARE * CHARS_PER_TOKEN;
  let tailStart = messages.length;
  let tailChars = 0;
  for (let i = messages.length - 1; i > head; i--) {
    tailChars += a.size(messages[i]!);
    if (tailChars > tailBudget && tailStart < messages.length) break;
    if (a.canStartTail(messages, i)) tailStart = i;
  }
  // Nothing older to sum up (one enormous recent exchange): cutting results is all that can be done.
  if (tailStart <= head + 1) return trimmed ? { trimmed, summarized: false, beforeTokens: before, afterTokens: afterTrim, budgetTokens } : undefined;

  const older = messages.slice(head, tailStart);
  let transcript = "";
  for (const m of older) {
    const r = a.render(m);
    transcript += `${r.length > RENDER_EACH ? `${r.slice(0, RENDER_EACH)}…` : r}\n\n`;
  }
  // Very long histories: the beginning (instructions, earlier memory) and the end matter most.
  // The summary call must fit the same model's window too (small local models).
  const renderTotal = Math.min(RENDER_TOTAL, Math.floor(budgetTokens * CHARS_PER_TOKEN * 0.7));
  if (transcript.length > renderTotal) transcript = `${transcript.slice(0, renderTotal * 0.4)}\n\n[… middle omitted …]\n\n${transcript.slice(-renderTotal * 0.6)}`;

  let text: string;
  let failed = false;
  try {
    text = (await summarize(SUMMARY_SYSTEM, transcript)).trim();
    if (text.length < 40) throw new Error("summary too short");
  } catch {
    if (options.signal?.aborted) return trimmed ? { trimmed, summarized: false, beforeTokens: before, afterTokens: afterTrim, budgetTokens } : undefined;
    failed = true;
    text =
      "The earlier part of this round was dropped to stay within the model's memory, and could not be summed up. Penteos still holds everything: read engagement.brief, the findings, the board and the recent runs before going on, and do not repeat work that is already recorded there.";
  }
  messages.splice(head, tailStart - head, ...a.memory(`${MEMORY_HEADER}\n\n${text}`));
  return { trimmed, summarized: true, ...(failed ? { summaryFailed: true } : {}), beforeTokens: before, afterTokens: estimateTokens(messages, a), budgetTokens };
}

/** Tells the operator, in one line, that the memory was summed up (cutting old results is silent). */
export function announce(o: MemoryOutcome | undefined, ctx: { emit(e: AgentEvent): void; lang?: Language }): void {
  if (!o?.summarized) return;
  ctx.emit({
    kind: "status",
    text: msg(ctx.lang ?? "en", o.summaryFailed ? "provider.status.compactedLossy" : "provider.status.compacted", { before: Math.round(o.beforeTokens / 1000), after: Math.round(o.afterTokens / 1000) }),
  });
}

/** The API said the conversation is longer than the model accepts. */
export function isContextOverflow(error: unknown): boolean {
  const e = error as { status?: number; code?: string; message?: string; error?: { code?: string; message?: string } };
  const text = `${e?.code ?? ""} ${e?.error?.code ?? ""} ${e?.message ?? ""} ${e?.error?.message ?? ""}`.toLowerCase();
  return /context[_ ]length|context window|maximum context|prompt is too long|too many tokens|input is too long|reduce the length|exceeds? the (?:model'?s )?(?:maximum|context)/.test(text);
}

const short = (s: string, n: number) => (s.length > n ? `${s.slice(0, n)}…` : s);
const json = (v: unknown) => {
  try {
    return typeof v === "string" ? v : JSON.stringify(v);
  } catch {
    return String(v);
  }
};

// ---------------------------------------------------------------------------------------------
// Adapters.

/** OpenAI Chat Completions messages (OpenAI, DeepSeek, local runtimes). */
type ChatMessage = { role: string; content?: unknown; tool_calls?: Array<{ id: string; function: { name: string; arguments: string } }>; tool_call_id?: string };

const chatText = (content: unknown): string =>
  typeof content === "string" ? content : Array.isArray(content) ? content.map((p) => (typeof p === "object" && p && "text" in p ? String((p as { text: unknown }).text) : "")).join("") : "";

export const chatAdapter: MemoryAdapter<ChatMessage> = {
  pinned: (ms) => (ms[0]?.role === "system" ? 1 : 0),
  size: (m) => chatText(m.content).length + json(m.tool_calls ?? "").length + 16,
  resultText: (m) => (m.role === "tool" ? chatText(m.content) : undefined),
  withResultText: (m, text) => ({ ...m, content: text }),
  // A tool message must follow the assistant message that called it: never start there.
  canStartTail: (ms, i) => ms[i]!.role === "user" || ms[i]!.role === "assistant",
  render: (m) => {
    if (m.role === "tool") return `TOOL RESULT: ${chatText(m.content)}`;
    if (m.role === "assistant") {
      const calls = (m.tool_calls ?? []).map((c) => `CALL ${c.function.name}(${short(c.function.arguments, 600)})`).join("\n");
      return `MAESTRO: ${chatText(m.content)}${calls ? `\n${calls}` : ""}`;
    }
    return `${m.role === "user" ? "OPERATOR/PENTEOS" : m.role.toUpperCase()}: ${chatText(m.content)}`;
  },
  memory: (text) => [{ role: "user", content: text }],
};

/** Anthropic Messages (Claude by API). */
type AnthropicBlock = { type: string; text?: string; name?: string; input?: unknown; content?: unknown; tool_use_id?: string; is_error?: boolean };
type AnthropicMessage = { role: "user" | "assistant"; content: string | AnthropicBlock[] };

const blockText = (c: unknown): string => (typeof c === "string" ? c : Array.isArray(c) ? c.map((b) => (typeof b === "object" && b && "text" in b ? String((b as { text: unknown }).text) : "")).join("") : "");

export const anthropicAdapter: MemoryAdapter<AnthropicMessage> = {
  pinned: () => 0,
  size: (m) => (typeof m.content === "string" ? m.content.length : json(m.content).length) + 16,
  // A user message made of tool results counts as one result (they come back together).
  resultText: (m) => (m.role === "user" && Array.isArray(m.content) && m.content.some((b) => b.type === "tool_result") ? m.content.map((b) => (b.type === "tool_result" ? blockText(b.content) : (b.text ?? ""))).join("\n") : undefined),
  // Each result keeps its block and id (the API pairs them with the calls) and is cut on its own.
  withResultText: (m) => {
    if (!Array.isArray(m.content)) return m;
    return {
      ...m,
      content: m.content.map((b) => {
        if (b.type !== "tool_result") return b;
        const own = blockText(b.content);
        return own.length > TRIM_OVER ? { ...b, content: `${own.slice(0, TRIM_TO)}… ${TRIM_NOTE}` } : b;
      }),
    };
  },
  // Messages alternate and the memory is a user message: the tail starts at an assistant message.
  canStartTail: (ms, i) => ms[i]!.role === "assistant",
  render: (m) => {
    if (typeof m.content === "string") return `${m.role === "user" ? "OPERATOR/PENTEOS" : "MAESTRO"}: ${m.content}`;
    return m.content
      .map((b) => {
        if (b.type === "text") return `${m.role === "user" ? "OPERATOR/PENTEOS" : "MAESTRO"}: ${b.text ?? ""}`;
        if (b.type === "tool_use") return `CALL ${b.name}(${short(json(b.input), 600)})`;
        if (b.type === "tool_result") return `TOOL RESULT${b.is_error ? " (error)" : ""}: ${blockText(b.content)}`;
        return "";
      })
      .filter(Boolean)
      .join("\n");
  },
  memory: (text) => [{ role: "user", content: text }],
};

/** OpenAI Responses items (the ChatGPT plan). */
type ResponseItem = { role?: string; content?: string; type?: string; call_id?: string; name?: string; arguments?: string; output?: string };

export const responsesAdapter: MemoryAdapter<ResponseItem> = {
  pinned: () => 0,
  size: (m) => (m.content ?? "").length + (m.arguments ?? "").length + (m.output ?? "").length + 16,
  resultText: (m) => (m.type === "function_call_output" ? (m.output ?? "") : undefined),
  withResultText: (m, text) => ({ ...m, output: text }),
  // A role item, or the first call of a group: never between calls whose outputs follow.
  canStartTail: (ms, i) => Boolean(ms[i]!.role) || (ms[i]!.type === "function_call" && ms[i - 1]?.type !== "function_call"),
  render: (m) => {
    if (m.type === "function_call") return `CALL ${m.name}(${short(m.arguments ?? "", 600)})`;
    if (m.type === "function_call_output") return `TOOL RESULT: ${m.output ?? ""}`;
    return `${m.role === "assistant" ? "MAESTRO" : "OPERATOR/PENTEOS"}: ${m.content ?? ""}`;
  },
  memory: (text) => [{ role: "user", content: text }],
};
