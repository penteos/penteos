import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { type Caller, type ChangeEvent, meterEgress, recordEvent, textForModel, type Language, type OperationContext, type Workspace } from "@penteos/core";
import { msg } from "./messages.js";
import { type AgentEvent, foldDelta, type ProviderSession, type ProviderSettings } from "./types.js";

/**
 * An agent with a job and a clean context (the verifier). Unlike the
 * Maestro it does not talk with the operator: it works, waits for the approvals and runs it
 * started, picks up the news by itself and ends when there is nothing left to wait for.
 */

const MAX_AUTO_TURNS = 8;
/** Nobody decided on its approvals or its runs never ended: give up instead of waiting forever. */
const MAX_WAIT_MS = 45 * 60 * 1000;

export interface SubAgentOptions {
  engagementId: string;
  /** Unique per job, e.g. "verifier-<findingId>": also the name of its transcript file. */
  key: string;
  caller: Caller;
  session: ProviderSession;
  settings: ProviderSettings;
  system: string;
  allow: (operation: string) => boolean;
  workspace: Workspace;
  dataDir: string;
  makeContext: (caller: Caller, engagementId: string) => OperationContext;
  onEvent: (event: AgentEvent) => void;
  /** Language of the people who read its transcript (the model always reads English). */
  lang?: () => Language;
  /** Whether it already closed its job (report, verdict). Without it, it gets one last turn to close. */
  closed?: () => boolean;
  /** That last turn's prompt: close now with what you have. */
  wrapUp?: string;
  /** The model runs on this machine (a local provider): its results are not masked. */
  localModel?: boolean;
  /** What to do when a target host goes down (the default: close with what you have if it matters). */
  onHostDown?: string;
}

export type SubAgentEnd = { reason: "finished" | "stopped" | "timeout" | "error"; error?: string };

const short = (text: string, max = 90) => (text.length > max ? `${text.slice(0, max)}…` : text);

export class SubAgent {
  readonly events: AgentEvent[] = [];
  private readonly approvals = new Set<string>();
  private readonly runs = new Set<string>();
  private readonly notices: string[] = [];
  private autoTurns = 0;
  private wrappedUp = false;
  private running?: AbortController;
  private ended = false;
  private waitTimer?: ReturnType<typeof setTimeout>;
  private readonly off: () => void;
  private resolveEnd!: (end: SubAgentEnd) => void;
  readonly done: Promise<SubAgentEnd> = new Promise((r) => (this.resolveEnd = r));

  get engagementId(): string {
    return this.o.engagementId;
  }

  constructor(private readonly o: SubAgentOptions) {
    const engagement = o.workspace.get(o.engagementId);
    const listener = (e: ChangeEvent) => this.onChange(e);
    engagement.events.on("change", listener);
    this.off = () => engagement.events.off("change", listener);
  }

  /** Where its transcript lives, with the engagement (it travels with exports). */
  static file(workspace: Workspace, engagementId: string, key: string): string {
    return join(workspace.get(engagementId).dir, "agent", "sub", `${key}.json`);
  }

  static transcript(workspace: Workspace, engagementId: string, key: string): AgentEvent[] {
    try {
      return (JSON.parse(readFileSync(SubAgent.file(workspace, engagementId, key), "utf8")) as { events: AgentEvent[] }).events;
    } catch {
      return [];
    }
  }

  start(prompt: string): Promise<SubAgentEnd> {
    void this.turn(prompt);
    return this.done;
  }

  stop(): void {
    this.running?.abort();
    this.end({ reason: "stopped" });
  }

  private emit(event: AgentEvent): void {
    if (this.ended && event.kind !== "done") return;
    const engagement = this.o.workspace.get(this.o.engagementId);
    let e = event;
    if (e.kind === "text" || e.kind === "notice" || e.kind === "delta") e = { ...e, text: engagement.redact(e.text) };
    if (e.kind === "tool") {
      if (e.approvalId) this.approvals.add(e.approvalId);
      if (e.runId) this.runs.add(e.runId);
    }
    if (e.kind === "delta") foldDelta(this.events, e.text);
    else this.events.push(e);
    if (this.events.length > 600) this.events.splice(0, this.events.length - 600);
    this.o.onEvent(e);
  }

  private save(): void {
    const file = SubAgent.file(this.o.workspace, this.o.engagementId, this.o.key);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(`${file}.tmp`, JSON.stringify({ version: 1, key: this.o.key, events: this.events }), { mode: 0o600 });
    renameSync(`${file}.tmp`, file);
  }

  private onChange(e: ChangeEvent): void {
    if (this.ended) return;
    if (e.type === "approval.resolved" && this.approvals.has(e.id)) {
      this.approvals.delete(e.id);
      if (e.runId) this.runs.add(e.runId);
      const what = short(e.summary);
      const L = this.L();
      if (e.approved && e.runId) this.news(`The operator accepted «${what}» and it is already running (run ${e.runId}): wait for the result with run_wait, do not repeat it.`, msg(L, "notice.approved.running", { what, run: e.runId }));
      else if (e.approved) this.news(`The operator accepted «${what}».`, msg(L, "notice.approved", { what }));
      else this.news(`The operator rejected «${what}». Do not do it; continue with what you can do without it.`, msg(L, "notice.rejected", { what }));
    }
    if (e.type === "oob.interaction" && (!e.requestedBy || e.requestedBy.id === this.o.caller.actor.id)) {
      this.news(
        `Out-of-band hit: the target made a ${e.protocol.toUpperCase()} request to your interaction host${e.purpose ? ` for «${e.purpose}»` : ""} (from ${e.remote}). The vulnerability is real. ${e.rawId ? `Save it as evidence with evidence_from_raw (rawId ${e.rawId})` : "Record it"}.`,
        msg(this.L(), "notice.oob", { protocol: e.protocol.toUpperCase(), purpose: e.purpose ?? "" }),
      );
    }
    // A host stopped answering (most likely a firewall ban): every agent hears it, not only the Maestro.
    if (e.type === "host.unreachable") {
      this.news(
        `${e.host} has refused or dropped ${e.failures} connections in a row since ${e.lastOkAt}: the target's firewall most likely blocked this machine's IP. Send it no more traffic. ${this.o.onHostDown ?? "If your job depends on that host, close it with what you have and say why."}`,
        msg(this.L(), "notice.hostUnreachable", { host: e.host }),
      );
    }
    if (e.type === "run.finished" && this.runs.has(e.id)) {
      this.runs.delete(e.id);
      const run = this.o.workspace.get(this.o.engagementId).getRun(e.id);
      if (run) {
        const L = this.L();
        this.news(
          `«${short(run.command ?? "")}» finished (run ${run.id}): ${run.status}${run.exitCode !== undefined ? `, exit code ${run.exitCode}` : ""}.`,
          msg(L, "notice.run", { command: short(run.command ?? ""), run: run.id, status: msg(L, `run.${run.status}`), code: run.exitCode !== undefined ? msg(L, "notice.run.code", { code: run.exitCode }) : "", ingested: "" }),
        );
      }
    }
  }


  /** After a turn: continue with news, keep waiting for what it started, or end. */
  private async next(): Promise<void> {
    if (this.ended || this.running) return;
    clearTimeout(this.waitTimer);
    if (this.notices.length) {
      if (this.autoTurns >= MAX_AUTO_TURNS) return this.finish();
      this.autoTurns++;
      const news = this.notices.splice(0);
      await this.turn(`[Penteos - news]\n${news.map((n) => `- ${n}`).join("\n")}\nContinue with your task.`);
      return;
    }
    if (this.approvals.size || this.runs.size) {
      this.emit({ kind: "status", text: msg(this.L(), this.approvals.size ? "status.waitingApproval" : "status.waitingRun") });
      this.waitTimer = setTimeout(() => this.end({ reason: "timeout" }), MAX_WAIT_MS);
      return;
    }
    await this.finish();
  }

  /**
   * About to end without having closed its job (out of steps or turns, or it simply stopped):
   * one last turn to hand over what it has, so the work is never lost without a report.
   */
  private async finish(): Promise<void> {
    if (this.o.closed && this.o.wrapUp && !this.wrappedUp && !this.o.closed()) {
      this.wrappedUp = true;
      this.notices.splice(0);
      try {
        recordEvent(this.o.workspace.get(this.o.engagementId), "wrapUp");
      } catch {
        /* gone */
      }
      this.emit({ kind: "status", text: msg(this.L(), "status.wrapUp") });
      await this.turn(`[Penteos - wrap up]\n${this.o.wrapUp}`);
      return;
    }
    this.end({ reason: "finished" });
  }

  private async turn(text: string): Promise<void> {
    if (this.ended) return;
    const controller = new AbortController();
    this.running = controller;
    let failed: string | undefined;
    try {
      const engagement = this.o.workspace.get(this.o.engagementId);
      const toModel = textForModel(engagement, text, { local: Boolean(this.o.localModel) });
      meterEgress(engagement, "system", this.o.system);
      meterEgress(engagement, "prompt", toModel);
      await this.o.session.send(toModel, {
        system: this.o.system,
        ops: { ...this.o.makeContext(this.o.caller, this.o.engagementId), modelIsLocal: Boolean(this.o.localModel) },
        caller: this.o.caller,
        settings: this.o.settings,
        workDir: join(this.o.workspace.get(this.o.engagementId).dir, "agent"),
        dataDir: this.o.dataDir,
        emit: (e) => this.emit(e),
        signal: controller.signal,
        allow: this.o.allow,
        lang: this.o.lang?.() ?? "en",
      });
    } catch (error) {
      if (!controller.signal.aborted) failed = (error as Error).message;
    } finally {
      this.running = undefined;
      this.save();
    }
    if (failed) {
      this.emit({ kind: "error", text: failed });
      return this.end({ reason: "error", error: failed });
    }
    await this.next();
  }

  private L(): Language {
    return this.o.lang?.() ?? "en";
  }

  /** News: English for the model, the reader's language for the transcript. */
  private news(model: string, human: string): void {
    this.notices.push(model);
    this.emit({ kind: "notice", text: human });
    setTimeout(() => void this.next(), 500);
  }

  private end(end: SubAgentEnd): void {
    if (this.ended) return;
    this.ended = true;
    clearTimeout(this.waitTimer);
    this.off();
    this.save();
    this.resolveEnd(end);
  }
}
