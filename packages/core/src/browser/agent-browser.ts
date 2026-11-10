import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { spawnTied } from "../tied.js";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Cdp } from "./cdp.js";
import { clickIn, fillIn, pageState } from "./page-scripts.js";

/**
 * The agents' browser: a headless Chromium per engagement that
 * goes through Penteos's proxy, so scope, history and evidence apply to every request it makes,
 * exactly as for the operator's project browser. One page per engagement keeps its session
 * (cookies, storage) between actions; actions run one at a time; it closes itself when idle.
 */

/** How the proxy tells this browser's traffic apart (proxy credentials "<engagementId>+agent"). */
export const AGENT_BROWSER_SOURCE = "agent";

/**
 * Chromium refuses to start as root with its sandbox on, and it checks before any of the app's
 * code runs: as root the flag must come on the command line (the operator's choice, see main.cjs).
 */
const rootFlags = (): string[] => (typeof process.getuid === "function" && process.getuid() === 0 ? ["--no-sandbox"] : []);

const IDLE_CLOSE_MS = 10 * 60 * 1000;

/**
 * Chrome's own housekeeping (accounts, device check-in, updates, safe browsing), not anything the
 * agent asked for. The proxy refuses it without filling the history with it.
 */
const HOUSEKEEPING = /^https?:\/\/(?:accounts\.google\.com\/ListAccounts|[a-z0-9-]+\.clients\.google\.com\/|clients[0-9]*\.google\.com\/|update\.googleapis\.com\/|safebrowsing\.googleapis\.com\/|optimizationguide-pa\.googleapis\.com\/|content-autofill\.googleapis\.com\/|[a-z0-9-]+\.gvt1\.com\/)/i;

export function isBrowserHousekeeping(url: string): boolean {
  return HOUSEKEEPING.test(url);
}
const NAV_TIMEOUT_MS = 30_000;

let proxy: { port: number; token: string } | undefined;

/** The server tells the browsers where its proxy listens; without it they cannot start. */
export function configureAgentBrowser(settings: { port: number; token: string } | undefined): void {
  proxy = settings;
}

/**
 * Penteos's own Chromium (the desktop app's Electron), as the app tells the core how to start it:
 * PENTEOS_AGENT_BROWSER = {"command": …, "args": […]}. Nothing to install. Without the desktop app
 * (a team server) it is the system's Chrome or Chromium instead.
 */
function ownBrowser(): { command: string; args: string[] } | undefined {
  const raw = process.env.PENTEOS_AGENT_BROWSER;
  if (!raw) return undefined;
  try {
    const v = JSON.parse(raw) as { command?: unknown; args?: unknown };
    if (typeof v.command === "string" && existsSync(v.command)) return { command: v.command, args: Array.isArray(v.args) ? v.args.map(String) : [] };
  } catch {
    /* a bad value: the system's browser, if any */
  }
  return undefined;
}

/** Which browser the agents get here: Penteos's own, the system's, or none. */
export function agentBrowserKind(): "penteos" | "system" | "none" {
  return ownBrowser() ? "penteos" : findChrome() ? "system" : "none";
}

/** The Chromium to use: PENTEOS_CHROME, or the first one installed. */
export function findChrome(): string | undefined {
  const env = process.env.PENTEOS_CHROME;
  if (env && existsSync(env)) return env;
  for (const name of ["google-chrome-stable", "google-chrome", "chromium", "chromium-browser"]) {
    const r = spawnSync("which", [name], { encoding: "utf8" });
    if (r.status === 0 && r.stdout.trim()) return r.stdout.trim();
  }
  return undefined;
}

export interface PageState {
  url: string;
  title: string;
  /** Visible text, trimmed. */
  text: string;
  links: Array<{ text: string; href: string }>;
  forms: Array<{ action: string; method: string; fields: Array<{ name: string; type: string; selector: string }> }>;
  buttons: Array<{ text: string; selector: string }>;
}

export interface BrowseResult {
  page: PageState;
  /** The requests this action caused (through the proxy, so they are in its history too). */
  requests: Array<{ method: string; url: string; status?: number; type?: string }>;
  /** Dialogs the page opened (alert, confirm, prompt): accepted and reported. */
  dialogs: Array<{ type: string; message: string }>;
  /** Uncaught errors and console.error lines. */
  console: string[];
  screenshot?: Buffer;
}

export type BrowseAction =
  | { action: "visit"; url: string; waitMs?: number }
  | { action: "click"; selector?: string; text?: string; waitMs?: number }
  | { action: "fill"; selector: string; value: string; submit?: boolean; waitMs?: number }
  | { action: "read" }
  | { action: "screenshot"; fullPage?: boolean };

/**
 * A function's source as an expression for Runtime.evaluate. Bundlers may wrap named functions in
 * a `__name` helper that does not exist in the page: a no-op one is provided.
 */
const call = (fn: (...args: never[]) => unknown, ...args: unknown[]) =>
  `(() => { const __name = (f) => f; return (${fn.toString()})(${args.map((a) => JSON.stringify(a ?? null)).join(", ")}); })()`;

class EngagementBrowser {
  private process?: ChildProcess;
  private profile?: string;
  private cdp?: Cdp;
  private session?: string;
  private queue: Promise<unknown> = Promise.resolve();
  private idle?: ReturnType<typeof setTimeout>;
  private inflight = new Set<string>();
  private lastNetwork = Date.now();
  private requests: BrowseResult["requests"] = [];
  private byId = new Map<string, BrowseResult["requests"][number]>();
  private dialogs: BrowseResult["dialogs"] = [];
  private console: string[] = [];

  constructor(
    private readonly engagementId: string,
    private readonly onClose: () => void,
  ) {}

  /** Actions run one at a time, in order. */
  run(action: BrowseAction): Promise<BrowseResult> {
    const next = this.queue.then(() => this.perform(action));
    this.queue = next.catch(() => undefined);
    return next;
  }

  private async start(): Promise<void> {
    if (this.cdp && !this.cdp.isClosed) return;
    if (!proxy) throw new Error("the agents' browser needs Penteos's proxy, and it is not running");
    const own = ownBrowser();
    const chrome = own ? undefined : findChrome();
    if (!own && !chrome) throw new Error("no browser for the agents: the desktop app brings its own; on a server, install Chromium or Chrome (or set PENTEOS_CHROME)");
    this.profile = mkdtempSync(join(tmpdir(), "penteos-browser-"));
    if (own) {
      // The app's own Chromium in its agent-browser mode: it ends when its stdin closes (when the core goes).
      const { ELECTRON_RUN_AS_NODE: _asNode, ...env } = process.env;
      this.process = spawn(own.command, [...own.args, ...rootFlags(), `--penteos-agent-browser=${this.profile}`, `--penteos-proxy-port=${proxy.port}`], {
        stdio: ["pipe", "ignore", "ignore"],
        detached: process.platform !== "win32",
        env: { ...env, PENTEOS_AGENT_PROXY_USER: `${this.engagementId}+${AGENT_BROWSER_SOURCE}`, PENTEOS_AGENT_PROXY_PASS: proxy.token },
      });
    } else this.process = spawnTied(
      chrome!,
      [
        "--headless=new",
        ...rootFlags(),
        `--user-data-dir=${this.profile}`,
        "--remote-debugging-port=0",
        `--proxy-server=http://127.0.0.1:${proxy.port}`,
        // Labs often live on localhost: through the proxy too.
        "--proxy-bypass-list=<-loopback>",
        // Every certificate it sees is Penteos's (the proxy intercepts TLS) in a throwaway profile.
        "--ignore-certificate-errors",
        // Nothing but the target: no update checks, sync, metrics or background requests of its own.
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--disable-default-apps",
        "--disable-extensions",
        "--metrics-recording-only",
        "--disable-client-side-phishing-detection",
        "--disable-component-extensions-with-background-pages",
        "--disable-domain-reliability",
        "--disable-breakpad",
        "--no-pings",
        "--password-store=basic",
        "--use-mock-keychain",
        "--disable-features=OptimizationHints,MediaRouter,Translate,AccountConsistency,DiceWebSigninInterception,ChromeSignin,PushMessaging,CertificateTransparencyComponentUpdater,AutofillServerCommunication",
        "--window-size=1366,900",
        "about:blank",
      ],
      { output: "ignore" },
    );
    this.process.once("exit", () => this.shutdown());
    const endpoint = await this.devtoolsEndpoint();
    this.cdp = await Cdp.connect(endpoint);
    // Chrome makes a new page; Penteos's own browser has one ready (Electron does not create targets).
    let targetId: string;
    try {
      ({ targetId } = await this.cdp.send<{ targetId: string }>("Target.createTarget", { url: "about:blank" }));
    } catch {
      const { targetInfos } = await this.cdp.send<{ targetInfos: Array<{ targetId: string; type: string }> }>("Target.getTargets", {});
      const page = targetInfos.find((t) => t.type === "page");
      if (!page) throw new Error("the browser has no page to work in");
      targetId = page.targetId;
    }
    const { sessionId } = await this.cdp.send<{ sessionId: string }>("Target.attachToTarget", { targetId, flatten: true });
    this.session = sessionId;
    this.listen();
    for (const domain of ["Page.enable", "Network.enable", "Runtime.enable"]) await this.cdp.send(domain, {}, sessionId);
    // Every request pauses for a moment so the proxy credentials can be given when it asks.
    await this.cdp.send("Fetch.enable", { handleAuthRequests: true, patterns: [{ urlPattern: "*" }] }, sessionId);
  }

  /** The DevTools address Chromium writes once it is listening. */
  private async devtoolsEndpoint(): Promise<string> {
    const file = join(this.profile!, "DevToolsActivePort");
    for (let i = 0; i < 100; i++) {
      if (existsSync(file)) {
        const [port, path] = readFileSync(file, "utf8").split("\n");
        if (port && path) return `ws://127.0.0.1:${port.trim()}${path.trim()}`;
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    this.shutdown();
    throw new Error("the browser did not start");
  }

  private listen(): void {
    const cdp = this.cdp!;
    const mine = (s?: string) => s === this.session;
    cdp.on("Fetch.requestPaused", (p, s) => {
      if (mine(s)) void cdp.send("Fetch.continueRequest", { requestId: p.requestId }, s).catch(() => undefined);
    });
    cdp.on("Fetch.authRequired", (p, s) => {
      if (!mine(s) || !proxy) return;
      const challenge = p.authChallenge as { source?: string } | undefined;
      const response = challenge?.source === "Proxy" ? { response: "ProvideCredentials", username: `${this.engagementId}+${AGENT_BROWSER_SOURCE}`, password: proxy.token } : { response: "CancelAuth" };
      void cdp.send("Fetch.continueWithAuth", { requestId: p.requestId, authChallengeResponse: response }, s).catch(() => undefined);
    });
    cdp.on("Network.requestWillBeSent", (p, s) => {
      if (!mine(s)) return;
      const req = p.request as { method: string; url: string };
      if (req.url.startsWith("data:")) return;
      const entry = { method: req.method, url: req.url, type: String(p.type ?? "") };
      this.byId.set(String(p.requestId), entry);
      this.requests.push(entry);
      this.inflight.add(String(p.requestId));
      this.lastNetwork = Date.now();
    });
    cdp.on("Network.responseReceived", (p, s) => {
      if (!mine(s)) return;
      const e = this.byId.get(String(p.requestId));
      if (e) e.status = (p.response as { status: number }).status;
    });
    for (const done of ["Network.loadingFinished", "Network.loadingFailed"]) {
      cdp.on(done, (p, s) => {
        if (!mine(s)) return;
        this.inflight.delete(String(p.requestId));
        this.lastNetwork = Date.now();
      });
    }
    cdp.on("Page.javascriptDialogOpening", (p, s) => {
      if (!mine(s)) return;
      this.dialogs.push({ type: String(p.type), message: String(p.message).slice(0, 500) });
      void cdp.send("Page.handleJavaScriptDialog", { accept: true }, s).catch(() => undefined);
    });
    cdp.on("Runtime.exceptionThrown", (p, s) => {
      if (!mine(s)) return;
      const d = p.exceptionDetails as { text?: string; exception?: { description?: string } };
      this.console.push((d.exception?.description ?? d.text ?? "error").split("\n")[0]!.slice(0, 300));
    });
    cdp.on("Runtime.consoleAPICalled", (p, s) => {
      if (!mine(s) || p.type !== "error") return;
      const args = (p.args as Array<{ value?: unknown; description?: string }>) ?? [];
      this.console.push(args.map((a) => String(a.value ?? a.description ?? "")).join(" ").slice(0, 300));
    });
  }

  private async evaluate<T>(expression: string): Promise<T> {
    const r = await this.cdp!.send<{ result: { value?: T }; exceptionDetails?: { text: string } }>("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true }, this.session);
    if (r.exceptionDetails) throw new Error(`the page script failed: ${r.exceptionDetails.text}`);
    return r.result.value as T;
  }

  /** Until the network has been quiet for a moment (or the time is up). */
  private async settle(maxMs: number): Promise<void> {
    const until = Date.now() + maxMs;
    while (Date.now() < until) {
      if (this.inflight.size === 0 && Date.now() - this.lastNetwork > 700) return;
      await new Promise((r) => setTimeout(r, 150));
    }
  }

  private async perform(action: BrowseAction): Promise<BrowseResult> {
    clearTimeout(this.idle);
    await this.start();
    this.requests = [];
    this.byId.clear();
    this.dialogs = [];
    this.console = [];
    const s = this.session;
    const cdp = this.cdp!;
    let screenshot: Buffer | undefined;
    try {
      if (action.action === "visit") {
        const loaded = new Promise<void>((resolve) => {
          const off = cdp.on("Page.loadEventFired", (_p, sid) => {
            if (sid === s) {
              off();
              resolve();
            }
          });
          setTimeout(() => {
            off();
            resolve();
          }, NAV_TIMEOUT_MS);
        });
        const nav = await cdp.send<{ errorText?: string }>("Page.navigate", { url: action.url }, s, NAV_TIMEOUT_MS);
        if (nav.errorText) throw new Error(`could not open ${action.url}: ${nav.errorText}`);
        await loaded;
        await this.settle(action.waitMs ?? 8000);
      } else if (action.action === "click") {
        const r = await this.evaluate<string>(call(clickIn as never, action.selector ?? null, action.text ?? null));
        if (r === "not_found") throw new Error(`nothing to click: ${action.selector ?? `text «${action.text}»`} is not on the page`);
        await this.settle(action.waitMs ?? 5000);
      } else if (action.action === "fill") {
        const r = await this.evaluate<string>(call(fillIn as never, action.selector, action.value, Boolean(action.submit)));
        if (r === "not_found") throw new Error(`no field ${action.selector} on the page`);
        await this.settle(action.waitMs ?? (action.submit ? 5000 : 500));
      } else if (action.action === "screenshot") {
        const shot = await cdp.send<{ data: string }>("Page.captureScreenshot", { format: "png", captureBeyondViewport: Boolean(action.fullPage) }, s, NAV_TIMEOUT_MS);
        screenshot = Buffer.from(shot.data, "base64");
      }
      const page = await this.evaluate<PageState>(call(pageState as never));
      return { page, requests: [...this.requests], dialogs: [...this.dialogs], console: [...this.console].slice(0, 20), ...(screenshot ? { screenshot } : {}) };
    } finally {
      this.idle = setTimeout(() => this.shutdown(), IDLE_CLOSE_MS);
    }
  }

  /** Closes the browser. Never throws: it also runs from timers and process exits. */
  shutdown(): void {
    clearTimeout(this.idle);
    this.cdp?.close();
    this.cdp = undefined;
    const child = this.process;
    const profile = this.profile;
    this.process = undefined;
    this.profile = undefined;
    // The profile goes once Chromium has exited: removing it while it is still writing fails.
    const clean = () => removeProfile(profile);
    if (child && child.exitCode === null && child.signalCode === null) {
      child.once("exit", clean);
      try {
        if (child.pid) process.kill(-child.pid, "SIGTERM");
      } catch {
        child.kill("SIGTERM");
      }
      // If it does not go quietly, force it after a moment.
      setTimeout(() => {
        try {
          if (child.exitCode === null && child.signalCode === null && child.pid) process.kill(-child.pid, "SIGKILL");
        } catch {
          /* already gone */
        }
      }, 3000).unref();
    } else clean();
    this.onClose();
  }
}

function removeProfile(dir: string | undefined, attempt = 0): void {
  if (!dir) return;
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  } catch {
    // A late write can still land: try a few more times, then leave it to the system's tmp cleanup.
    if (attempt < 5) setTimeout(() => removeProfile(dir, attempt + 1), 300).unref();
  }
}

const browsers = new Map<string, EngagementBrowser>();

/** Runs an action in the engagement's browser, starting it if needed. */
export function browse(engagementId: string, action: BrowseAction): Promise<BrowseResult> {
  let b = browsers.get(engagementId);
  if (!b) {
    b = new EngagementBrowser(engagementId, () => browsers.delete(engagementId));
    browsers.set(engagementId, b);
  }
  return b.run(action);
}

/** Whether the engagement's browser is open (it keeps the session between actions). */
export function browserOpen(engagementId: string): boolean {
  return browsers.has(engagementId);
}

export function closeBrowser(engagementId: string): void {
  browsers.get(engagementId)?.shutdown();
}

export function closeAllBrowsers(): void {
  for (const b of [...browsers.values()]) b.shutdown();
}
