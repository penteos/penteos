import type { CoreClient } from "../client";

/**
 * Interface errors reach the core, which writes them to its log (logs/core.log): the file to
 * attach to a bug report.
 */
let core: CoreClient | undefined;

export function reportErrorsTo(client: CoreClient): void {
  core = client;
  window.addEventListener("error", (e) => reportError("window", e.error ?? e.message));
  window.addEventListener("unhandledrejection", (e) => reportError("promise", e.reason));
}

export function reportError(where: string, error: unknown): void {
  try {
    const e = error instanceof Error ? error : new Error(String(error));
    core?.notify("ui.error", { where, message: e.message, stack: (e.stack ?? "").slice(0, 4000) });
  } catch {
    /* reporting must never fail the interface */
  }
}
