import OpenAI from "openai";
import type { ProviderSession, TurnContext } from "../types.js";
import { msg } from "../messages.js";
import { recordEvent } from "@penteos/core";
import { agentOperations, displayToolName, LAST_STEP_NOTE, runTool, toolName, toolSchema } from "../tools.js";
import { announce, chatAdapter, isContextOverflow, keepWithinBudget, memoryBudget, type MemoryAdapter } from "../memory.js";
import { CUT_RETRIES, isCutConnection, timing } from "../failover.js";

const MAX_STEPS = 40;
/** A turn that comes back with nothing (no text, no tool call) is asked again this many times. */
const EMPTY_RETRIES = 1;

type Message = OpenAI.Chat.ChatCompletionMessageParam;

/**
 * Makes a history acceptable to strict servers (DeepSeek, OpenAI): an assistant message must have
 * text or tool calls, every tool call needs an id, and a tool result must answer a call. One empty
 * assistant turn would make every later request fail with a 400, so a stored conversation is
 * repaired when loaded and before each request.
 */
export function sanitizeHistory(messages: Message[]): Message[] {
  const out: Message[] = [];
  const open = new Set<string>();
  let n = 0;
  for (const m of messages) {
    if (m.role === "assistant") {
      const a = m as OpenAI.Chat.ChatCompletionAssistantMessageParam;
      const calls = (a.tool_calls ?? []).map((c) => (c.id ? c : { ...c, id: `call_repaired_${++n}` }));
      const text = typeof a.content === "string" ? a.content : Array.isArray(a.content) ? a.content.length : a.content;
      if (!text && calls.length === 0) continue;
      for (const c of calls) open.add(c.id);
      out.push({ ...a, ...(calls.length ? { tool_calls: calls } : {}) });
    } else if (m.role === "tool") {
      const t = m as OpenAI.Chat.ChatCompletionToolMessageParam;
      if (!open.has(t.tool_call_id)) continue;
      open.delete(t.tool_call_id);
      out.push(t);
    } else out.push(m);
  }
  return out;
}

/**
 * Any server that speaks the OpenAI Chat Completions API with tool calling: OpenAI itself,
 * DeepSeek, and local runtimes (Ollama, LM Studio, llama.cpp, vLLM). Penteos runs the loop.
 */
export class OpenAICompatibleSession implements ProviderSession {
  private readonly messages: OpenAI.Chat.ChatCompletionMessageParam[];
  /** The model's window as learned from an overflow, when smaller than the budget. */
  private window?: number;

  constructor(
    private readonly defaults: { baseUrl?: string; model: string; apiKeyRequired: boolean },
    state?: unknown,
  ) {
    this.messages = Array.isArray((state as { messages?: unknown })?.messages) ? sanitizeHistory((state as { messages: Message[] }).messages) : [];
    // A restart in the middle of a turn can leave tool calls without results: close them.
    const lastAssistant = [...this.messages].reverse().find((m) => m.role === "assistant") as OpenAI.Chat.ChatCompletionAssistantMessageParam | undefined;
    const answered = new Set(this.messages.filter((m) => m.role === "tool").map((m) => (m as OpenAI.Chat.ChatCompletionToolMessageParam).tool_call_id));
    for (const call of lastAssistant?.tool_calls ?? []) {
      if (!answered.has(call.id)) this.messages.push({ role: "tool", tool_call_id: call.id, content: "Interrupted: Penteos restarted before this call finished. Check its state before retrying." });
    }
  }

  snapshot(): unknown {
    return { messages: this.messages };
  }

  async send(text: string, ctx: TurnContext): Promise<void> {
    const baseURL = ctx.settings.baseUrl || this.defaults.baseUrl;
    const client = new OpenAI({
      apiKey: ctx.settings.apiKey || (this.defaults.apiKeyRequired ? undefined : "local"),
      ...(baseURL ? { baseURL } : {}),
    });
    const model = ctx.settings.model || this.defaults.model;
    const tools: OpenAI.Chat.ChatCompletionTool[] = agentOperations(ctx.allow).map((op) => ({
      type: "function",
      function: { name: toolName(op.name), description: op.description, parameters: toolSchema(op.name) },
    }));
    if (this.messages.length === 0) this.messages.push({ role: "system", content: ctx.system });
    this.messages.splice(0, this.messages.length, ...sanitizeHistory(this.messages));
    this.messages.push({ role: "user", content: text });

    // A long round stays within the model's memory: old results are cut, the older part summed up.
    const budget = () => Math.min(ctx.memoryTokens ?? memoryBudget(!this.defaults.apiKeyRequired), this.window ?? Infinity);
    const summarize = async (system: string, transcript: string) => {
      const r = await client.chat.completions.create({ model, messages: [{ role: "system", content: system }, { role: "user", content: transcript }], max_tokens: 6000 }, { signal: ctx.signal });
      return r.choices[0]?.message?.content ?? "";
    };
    const remember = async (force = false) => {
      const outcome = await keepWithinBudget(this.messages, chatAdapter as unknown as MemoryAdapter<Message>, budget(), summarize, { force, signal: ctx.signal });
      if (outcome) this.messages.splice(0, this.messages.length, ...sanitizeHistory(this.messages));
      if (force && outcome) this.window = outcome.budgetTokens;
      announce(outcome, ctx);
    };

    let emptyRetries = 0;
    let overflowRetried = false;
    let cutRetries = 0;
    for (let step = 0; step < MAX_STEPS; step++) {
      if (ctx.signal.aborted) return;
      await remember();
      let content = "";
      let reasoning = 0;
      const calls = new Map<number, { id: string; name: string; args: string }>();
      try {
        let stream: AsyncIterable<OpenAI.Chat.ChatCompletionChunk>;
        try {
          stream = await client.chat.completions.create({ model, messages: this.messages, tools, ...(step === MAX_STEPS - 1 ? { tool_choice: "none" as const } : {}), stream: true }, { signal: ctx.signal });
          overflowRetried = false;
        } catch (error) {
          // The model's window is smaller than the budget assumed: compact now and try once more.
          if (!ctx.signal.aborted && !overflowRetried && isContextOverflow(error)) {
            overflowRetried = true;
            await remember(true);
            step--;
            continue;
          }
          throw error;
        }
        let finished = false;
        for await (const chunk of stream) {
          if (chunk.choices[0]?.finish_reason) finished = true;
          const delta = chunk.choices[0]?.delta;
          if (!delta) continue;
          if (delta.content) {
            content += delta.content;
            ctx.emit({ kind: "delta", text: delta.content });
          }
          // Reasoning models (DeepSeek, gpt-oss…) stream their thinking apart; it is not the answer.
          const thinking = (delta as { reasoning_content?: unknown; reasoning?: unknown }).reasoning_content ?? (delta as { reasoning?: unknown }).reasoning;
          if (typeof thinking === "string") reasoning += thinking.length;
          for (const call of delta.tool_calls ?? []) {
            const current = calls.get(call.index) ?? { id: "", name: "", args: "" };
            if (call.id) current.id = call.id;
            if (call.function?.name) current.name += call.function.name;
            if (call.function?.arguments) current.args += call.function.arguments;
            calls.set(call.index, current);
          }
        }
        // A stream that ends without saying it finished was cut: the answer is not whole.
        if (!finished) throw new Error("terminated: the answer stopped before it was complete");
        cutRetries = 0;
      } catch (error) {
        // The connection dropped mid-answer: nothing was stored, ask for this step again.
        if (!ctx.signal.aborted && isCutConnection(error) && cutRetries < CUT_RETRIES) {
          cutRetries++;
          ctx.emit({ kind: "status", text: msg(ctx.lang ?? "en", "provider.status.reconnecting", { n: cutRetries, max: CUT_RETRIES }) });
          await new Promise((r) => setTimeout(r, timing.cutDelayMs * cutRetries));
          step--;
          continue;
        }
        throw error;
      }

      const toolCalls = [...calls.values()].filter((c) => c.name).map((c, i) => ({ ...c, id: c.id || `call_${Date.now().toString(36)}_${step}_${i}` }));
      // Nothing came back: never stored (it would break every later request); asked once more, then said.
      if (!content.trim() && toolCalls.length === 0) {
        if (emptyRetries++ < EMPTY_RETRIES) {
          step--;
          continue;
        }
        ctx.emit({ kind: "error", text: msg(ctx.lang ?? "en", reasoning > 0 ? "provider.error.thoughtOnly" : "provider.error.empty") });
        return;
      }
      this.messages.push({
        role: "assistant",
        content: content || null,
        ...(toolCalls.length
          ? { tool_calls: toolCalls.map((c) => ({ id: c.id, type: "function" as const, function: { name: c.name, arguments: c.args || "{}" } })) }
          : {}),
      });
      if (toolCalls.length === 0) return;

      for (const call of toolCalls) {
        let input: unknown;
        try {
          input = JSON.parse(call.args || "{}");
        } catch {
          this.messages.push({ role: "tool", tool_call_id: call.id, content: "INVALID_JSON: the arguments were not valid JSON; call the tool again." });
          continue;
        }
        ctx.emit({ kind: "tool", id: call.id, name: displayToolName(call.name), input, status: "running" });
        const outcome = await runTool(call.name, input, ctx.ops, ctx.allow);
        ctx.emit({ kind: "tool", id: call.id, name: displayToolName(call.name), input, status: outcome.ok ? "ok" : "error", summary: outcome.summary, ...(outcome.approvalId ? { approvalId: outcome.approvalId } : {}), ...(outcome.runId ? { runId: outcome.runId } : {}) });
        this.messages.push({ role: "tool", tool_call_id: call.id, content: outcome.content });
      }
      if (step === MAX_STEPS - 2) {
        this.messages.push({ role: "user", content: LAST_STEP_NOTE });
        ctx.emit({ kind: "status", text: msg(ctx.lang ?? "en", "provider.status.lastStep", { n: MAX_STEPS }) });
        try {
          recordEvent(ctx.ops.engagement(), "stepLimit");
        } catch {
          /* no engagement */
        }
      }
    }
    ctx.emit({ kind: "error", text: msg(ctx.lang ?? "en", "provider.error.maxSteps", { n: MAX_STEPS }) });
  }
}
