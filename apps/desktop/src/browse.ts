import type { CoreClient } from "./client";
import { t } from "./i18n";
import { openProjectBrowser } from "./panels/Proxy";
import type { EngagementInfo, Entity } from "./state";
import { toast } from "./ui/bits";

/**
 * Browsing requests (browser.request): the Maestro asks the operator to browse something only a
 * person can (an anti-bot challenge, a login with captcha or MFA). The request opens the project
 * browser with the Maestro's note on top; the note counts what the proxy records, and "Done" - in
 * the browser or on the card - tells the Maestro how much was captured.
 */

export interface BrowseSpec {
  url: string;
  steps: string[];
  requestedAt: string;
  result?: { outcome: "done" | "declined"; exchanges: number; hosts: string[] };
}

export const browseOf = (task: Entity): BrowseSpec | undefined => task.attributes.browse as BrowseSpec | undefined;

/** Notes open in a browser window, by task. */
const open = new Map<string, { engagementId: string }>();

export async function openBrowseRequest(client: CoreClient, engagement: EngagementInfo | undefined, task: Entity): Promise<void> {
  const b = browseOf(task);
  if (!engagement || !b) return;
  const p = await client.call<{ exchanges: number; hosts: string[] }>("browser.progress", { taskId: task.id }).catch(() => ({ exchanges: 0, hosts: [] }));
  open.set(task.id, { engagementId: engagement.id });
  await openProjectBrowser(client, engagement, b.url, { taskId: task.id, title: String(task.attributes.title), url: b.url, steps: b.steps, exchanges: p.exchanges, hosts: p.hosts });
  void client.call("task.update", { id: task.id, status: "in_progress" }).catch(() => undefined);
}

/** Tells the Maestro the operator finished (or declined), and closes the note in the browser. */
export async function respondBrowse(client: CoreClient, taskId: string, outcome: "done" | "declined"): Promise<void> {
  const r = await client.call<{ exchanges: number }>("browser.respond", { taskId, outcome });
  const note = open.get(taskId);
  if (note) {
    open.delete(taskId);
    void window.penteosDesktop?.updateBrowserNote?.({ engagementId: note.engagementId, taskId, sent: outcome === "done" ? t("work.browse.sent", { n: r.exchanges }) : t("work.browse.declinedSent") });
  }
  toast("ok", outcome === "done" ? t("work.browse.sentToast") : t("work.browse.declinedToast"), outcome === "done" ? t("work.browse.sent", { n: r.exchanges }) : undefined);
}

/**
 * Keeps the notes in the browser up to date (exchanges recorded so far) and handles "Done" pressed
 * inside the browser. Returns the cleanup.
 */
export function startBrowseBridge(client: CoreClient, openPanel: (id: "scope") => void = () => {}): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const refresh = () => {
    timer = undefined;
    for (const [taskId, note] of open) {
      client
        .call<{ exchanges: number; hosts: string[] }>("browser.progress", { taskId })
        .then((p) => window.penteosDesktop?.updateBrowserNote?.({ engagementId: note.engagementId, taskId, exchanges: p.exchanges, hosts: p.hosts }))
        .catch(() => open.delete(taskId));
    }
  };
  const offEvents = client.onEvent((e) => {
    if (e.type === "proxy.entry" && open.size && !timer) timer = setTimeout(refresh, 600);
  });
  const offAction = window.penteosDesktop?.onBrowserNoteAction?.((p) => {
    if (p.action !== "done") return;
    if (!open.has(p.taskId)) open.set(p.taskId, { engagementId: p.engagementId });
    respondBrowse(client, p.taskId, "done").catch((err: Error) => toast("bad", t("work.browse.failed"), err.message));
  });
  const offBlock = window.penteosDesktop?.onBrowserBlockAction?.((p) => {
    if (p.action === "open_scope") return openPanel("scope");
    void resolveBlock(client, p);
  });
  return () => {
    offEvents();
    offAction?.();
    offBlock?.();
    if (timer) clearTimeout(timer);
  };
}

/**
 * The way out of a page the proxy blocked, chosen by the operator in the browser. The operator is
 * the authority: the narrowest scope rule (that exact host, and its port if the address names
 * one), a pass for a while, or lifting the pause. The agents never come through here: they propose.
 */
export async function resolveBlock(client: CoreClient, p: { engagementId: string; action: string; host: string; url?: string }): Promise<void> {
  const done = (r: { done?: boolean; error?: string }) => window.penteosDesktop?.resolveBrowserBlock?.({ engagementId: p.engagementId, ...r });
  try {
    if (p.action === "add_scope") {
      await client.call("scope.add_rule", { engagementId: p.engagementId, rule: scopeRuleFor(p.host, p.url) });
      toast("ok", t("web.browser.block.addedToast", { host: p.host }));
    } else if (p.action === "let_through") {
      await client.call("proxy.let_through", { engagementId: p.engagementId, host: p.host });
      toast("info", t("web.browser.block.letThroughToast", { host: p.host }));
    } else if (p.action === "resume") {
      await client.call("engagement.resume_work", { engagementId: p.engagementId });
      toast("ok", t("web.browser.block.resumedToast"));
    } else return;
    await done({ done: true });
  } catch (err) {
    await done({ error: (err as Error).message });
  }
}

/** The narrowest inclusion rule for what the operator was opening. */
export function scopeRuleFor(host: string, url?: string): { effect: "include"; target: { type: "ip" | "domain"; value: string }; ports?: string } {
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
  let port = "";
  try {
    port = url ? new URL(url).port : "";
  } catch {
    /* no port named */
  }
  return { effect: "include", target: { type: isIp ? "ip" : "domain", value: host }, ...(port ? { ports: port } : {}) };
}
