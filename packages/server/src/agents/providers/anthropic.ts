import Anthropic from "@anthropic-ai/sdk";
import type { ProviderSession, TurnContext } from "../types.js";
import { msg } from "../messages.js";
import { recordEvent } from "@penteos/core";
import { agentOperations, displayToolName, LAST_STEP_NOTE, runTool, toolName, toolSchema } from "../tools.js";
import { announce, anthropicAdapter, isContextOverflow, keepWithinBudget, memoryBudget, type MemoryAdapter } from "../memory.js";

const DEFAULT_MODEL = "claude-opus-5-5";
const MAX_STEPS = 40;

/**
 * Claude API provider: Penteos runs the agent loop itself (streaming manual loop), so every tool
 * call goes through executeOperation with the agent's identity, scope checks and audit.
 */
export class AnthropicSession implements ProviderSession {
  /**
   * The history. Earlier turns are only changed when the round outgrows the model's memory (old
   * results cut, the older part summed up: see memory.ts); the recent turns, thinking included,
   * stay as they were.
   */
  private readonly messages: Anthropic.Beta.BetaMessageParam[];
  /** The model's window as learned from an overflow, when smaller than the budget. */
  private window?: number;

  constructor(state?: unknown) {
    this.messages = Array.isArray((state as { messages?: unknown })?.messages) ? ((state as { messages: Anthropic.Beta.BetaMessageParam[] }).messages) : [];
    // A restart in the middle of a turn can leave tool calls without results: close them.
    const last = this.messages.at(-1);
    if (last?.role === "assistant" && Array.isArray(last.content)) {
      const pending = last.content.filter((b): b is Anthropic.Beta.BetaToolUseBlock => typeof b === "object" && b.type === "tool_use");
      if (pending.length) {
        this.messages.push({
          role: "user",
          content: pending.map((b) => ({ type: "tool_result" as const, tool_use_id: b.id, content: "Interrupted: Penteos restarted before this call finished. Check its state before retrying.", is_error: true })),
        });
      }
    }
  }

  snapshot(): unknown {
    return { messages: this.messages };
  }

  async send(text: string, ctx: TurnContext): Promise<void> {
    const client = new Anthropic(ctx.settings.apiKey ? { apiKey: ctx.settings.apiKey } : {});
    const tools: Anthropic.Beta.BetaTool[] = agentOperations(ctx.allow).map((op) => ({
      name: toolName(op.name),
      description: op.description,
      input_schema: toolSchema(op.name) as Anthropic.Beta.BetaTool.InputSchema,
      eager_input_streaming: true,
    }));
    this.messages.push({ role: "user", content: text });
    let jsonRetries = 0;
    const model = ctx.settings.model || DEFAULT_MODEL;
    const budget = () => Math.min(ctx.memoryTokens ?? memoryBudget(false), this.window ?? Infinity);
    const summarize = async (system: string, transcript: string) => {
      const r = await client.beta.messages.create({ model, max_tokens: 8000, system, messages: [{ role: "user", content: transcript }] }, { signal: ctx.signal });
      return r.content.map((b) => (b.type === "text" ? b.text : "")).join("");
    };
    const remember = async (force = false) => {
      const outcome = await keepWithinBudget(this.messages, anthropicAdapter as unknown as MemoryAdapter<Anthropic.Beta.BetaMessageParam>, budget(), summarize, { force, signal: ctx.signal });
      if (force && outcome) this.window = outcome.budgetTokens;
      announce(outcome, ctx);
    };
    let overflowRetried = false;

    for (let step = 0; step < MAX_STEPS; step++) {
      if (ctx.signal.aborted) return;
      await remember();
      const stream = client.beta.messages.stream(
        {
          model,
          max_tokens: 64000,
          system: [{ type: "text", text: ctx.system, cache_control: { type: "ephemeral" } }],
          tools,
          // The last step closes with words, not with a half-finished action.
          ...(step === MAX_STEPS - 1 ? { tool_choice: { type: "none" as const } } : {}),
          messages: this.messages,
          thinking: { type: "adaptive" },
          output_config: { effort: "high" },
          // Security work can trip safety classifiers; let the API retry on a fallback model.
          betas: ["server-side-fallback-2026-07-01"],
          fallbacks: "default",
        },
        { signal: ctx.signal },
      );
      stream.on("text", (delta) => ctx.emit({ kind: "delta", text: delta }));

      let message: Anthropic.Beta.BetaMessage;
      try {
        message = await stream.finalMessage();
        jsonRetries = 0;
        overflowRetried = false;
      } catch (error) {
        if (ctx.signal.aborted) return;
        // The model's window is smaller than the budget assumed: compact now and try once more.
        if (!overflowRetried && isContextOverflow(error)) {
          overflowRetried = true;
          await remember(true);
          step--;
          continue;
        }
        if (error instanceof Anthropic.APIError || jsonRetries++ >= 2) throw error;
        ctx.emit({ kind: "status", text: msg(ctx.lang ?? "en", "provider.status.badToolInput") });
        continue;
      }

      if (message.stop_reason === "refusal") {
        ctx.emit({ kind: "error", text: msg(ctx.lang ?? "en", "provider.error.refused", { category: message.stop_details?.category ? ` (${message.stop_details.category})` : "" }) });
        return;
      }
      if (message.stop_reason === "pause_turn") {
        this.messages.push({ role: "assistant", content: message.content });
        continue;
      }

      const toolUses = message.content.filter((b): b is Anthropic.Beta.BetaToolUseBlock => b.type === "tool_use");
      if (toolUses.length === 0) {
        this.messages.push({ role: "assistant", content: message.content });
        return;
      }
      if (message.stop_reason === "max_tokens") {
        ctx.emit({ kind: "error", text: msg(ctx.lang ?? "en", "provider.error.truncated") });
        return;
      }

      this.messages.push({ role: "assistant", content: message.content });
      // Parallel tool calls: run them all, return every result in a single user message.
      const results = await Promise.all(
        toolUses.map(async (use) => {
          ctx.emit({ kind: "tool", id: use.id, name: displayToolName(use.name), input: use.input, status: "running" });
          const outcome = await runTool(use.name, use.input, ctx.ops, ctx.allow);
          ctx.emit({ kind: "tool", id: use.id, name: displayToolName(use.name), input: use.input, status: outcome.ok ? "ok" : "error", summary: outcome.summary, ...(outcome.approvalId ? { approvalId: outcome.approvalId } : {}), ...(outcome.runId ? { runId: outcome.runId } : {}) });
          return { type: "tool_result" as const, tool_use_id: use.id, content: outcome.content, ...(outcome.ok ? {} : { is_error: true }) };
        }),
      );
      const last = step === MAX_STEPS - 2;
      this.messages.push({ role: "user", content: last ? [...results, { type: "text" as const, text: LAST_STEP_NOTE }] : results });
      if (last) {
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
