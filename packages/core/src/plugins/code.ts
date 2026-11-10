import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, readlinkSync, realpathSync, writeFileSync } from "node:fs";
import { setPriority } from "node:os";
import { join, resolve, sep } from "node:path";
import { offlineSandbox } from "../sandbox.js";
import { lsofConnections, psTable, treeOf } from "./procinfo.js";
import { CODE_RUNNER_SOURCE } from "./code-runner.js";
import { PYTHON_RUNNER_SOURCE } from "./python-runner.js";
import type { PluginData } from "./data.js";
import { storageActivationError } from "./data.js";
import type { LoadedPlugin, PluginActivator } from "./host.js";
import type { PluginRuntime } from "./runtime.js";

/**
 * Code plugins: each one in a process of its own.
 *
 * Isolation, always (any Linux, with the Node that ships with Penteos): Node's permission model -
 * it reads only the runner and its own folder; it cannot write files, start processes or workers,
 * or load native addons -, the network taken away before its code loads (see code-runner.ts), a
 * clean environment (no API keys of the operator's), and a memory cap. Where the system allows it
 * (bubblewrap or a network namespace), the kernel also takes the network away.
 *
 * Failures: a call that does not answer in time kills the process (a busy loop cannot be stopped
 * any other way); a process that dies (a crash, out of memory) fails its calls and counts as a
 * crash toward the breaker; the next call starts it again. The breaker turns it off for good.
 */

function pickEnv(keys: string[]): Record<string, string> {
  return Object.fromEntries(keys.filter((k) => process.env[k] !== undefined).map((k) => [k, process.env[k]!]));
}

/** Writes the Python runner where the host keeps its files and returns its path. */
function pythonRunnerFile(hostDir: string): string {
  const hash = createHash("sha256").update(PYTHON_RUNNER_SOURCE).digest("hex").slice(0, 12);
  const file = join(hostDir, `python-runner-${hash}.py`);
  if (!existsSync(file)) {
    mkdirSync(hostDir, { recursive: true });
    writeFileSync(file, PYTHON_RUNNER_SOURCE, { mode: 0o444 });
  }
  return file;
}

export interface CodeLimits {
  /** Hard ceiling for the process's data (heap, buffers, WebAssembly), set by the kernel (ulimit -d). */
  memoryMb: number;
  /** The same ceiling for a free plugin: wide, only so a runaway one cannot take the machine. */
  freeMemoryMb: number;
  /** V8's own heap ceiling, inside the one above. */
  heapMb: number;
  activationMs: number;
  /** Requests to the core in one call. */
  rpcPerCall: number;
  /** One message from the plugin, in bytes; a bigger one ends the process. */
  messageBytes: number;
  /** Messages per window; more end the process (a plugin flooding the core). */
  messagesPerWindow: number;
  windowMs: number;
  /** Busy while nobody called it: this share of a CPU for `busySamples` samples in a row ends the process. */
  idleCpuShare: number;
  busySamples: number;
  sampleMs: number;
  /** No call for this long: the process stops (it starts again on the next call). */
  idleStopMs: number;
}

export const CODE_LIMITS: CodeLimits = {
  memoryMb: 384,
  freeMemoryMb: 4096,
  heapMb: 128,
  activationMs: 10_000,
  rpcPerCall: 2000,
  // Room for a parser's results (an imported scan); the channel still ends a process past it.
  messageBytes: 16 * 1024 * 1024,
  messagesPerWindow: 5000,
  windowMs: 10_000,
  idleCpuShare: 0.5,
  busySamples: 3,
  sampleMs: 2000,
  idleStopMs: 5 * 60_000,
};

/** Code plugin processes running at once; past it the one idle the longest stops. */
export const MAX_CODE_PROCESSES = 8;
const running = new Set<CodePluginProcess>();

/** free: a normal process the operator trusted (watched, not limited); kernel/process: isolated. */
export type Isolation = "free" | "kernel" | "process";

/** Writes the runner where the host keeps its files (once per content) and returns its path. */
function runnerFile(hostDir: string): string {
  const hash = createHash("sha256").update(CODE_RUNNER_SOURCE).digest("hex").slice(0, 12);
  const file = join(hostDir, `code-runner-${hash}.mjs`);
  if (!existsSync(file)) {
    mkdirSync(hostDir, { recursive: true });
    writeFileSync(file, CODE_RUNNER_SOURCE, { mode: 0o444 });
  }
  return file;
}

const ceilings = new Map<string, number | null>();

/**
 * The lowest kernel memory ceiling (ulimit -d, MB) this Node starts under, from the one wanted up:
 * Penteos's own (Electron) starts under 256 MB, a stand-alone Node needs more just to start. Probed
 * once with empty starts of a few milliseconds. undefined: no ceiling can be set here.
 */
export function memoryCeiling(execPath: string, wantedMb: number, probe: string[] = ["-e", "0"]): number | undefined {
  const key = `${execPath}|${wantedMb}|${probe.join(" ")}`;
  const known = ceilings.get(key);
  if (known !== undefined) return known ?? undefined;
  let found: number | null = null;
  if (process.platform === "linux" || process.platform === "darwin") {
    for (const mb of [wantedMb, 512, 1024, 2048, 4096, 8192].filter((m, i, a) => m >= wantedMb && a.indexOf(m) === i)) {
      try {
        const r = spawnSync("/bin/sh", ["-c", `ulimit -d ${mb * 1024} || exit 99; exec "$@"`, "probe", execPath, ...probe], { env: { ELECTRON_RUN_AS_NODE: "1", PATH: process.env.PATH ?? "/usr/bin:/bin" }, stdio: "ignore", timeout: 5000 });
        if (r.status === 0) {
          found = mb;
          break;
        }
        if (r.status === 99) break;
      } catch {
        break;
      }
    }
  }
  ceilings.set(key, found);
  return found ?? undefined;
}

/** A process and everything it started (bwrap runs the plugin as its child). */
function processTree(pid: number): number[] {
  if (process.platform === "darwin") return treeOf(psTable(), pid);
  const out = [pid];
  for (let i = 0; i < out.length && out.length < 64; i++) {
    try {
      for (const task of readdirSync(`/proc/${out[i]}/task`)) {
        const children = readFileSync(`/proc/${out[i]}/task/${task}/children`, "utf8").trim();
        if (children) out.push(...children.split(/\s+/).map(Number).filter(Number.isFinite));
      }
    } catch {
      /* gone, or /proc not readable */
    }
  }
  return out;
}

const hexIp4 = (h: string) => [3, 2, 1, 0].map((i) => parseInt(h.slice(i * 2, i * 2 + 2), 16)).join(".");
function hexIp6(h: string): string {
  // Four 32-bit words, each little-endian.
  const bytes: number[] = [];
  for (let w = 0; w < 4; w++) for (let b = 3; b >= 0; b--) bytes.push(parseInt(h.slice(w * 8 + b * 2, w * 8 + b * 2 + 2), 16));
  if (bytes.slice(0, 10).every((x) => x === 0) && bytes[10] === 255 && bytes[11] === 255) return bytes.slice(12).join(".");
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(((bytes[i]! << 8) | bytes[i + 1]!).toString(16));
  return groups.join(":");
}

/** Established connections of a process tree to other machines (Linux /proc): what went around the proxy. */
export function connectionsOf(pids: number[]): Array<{ ip: string; port: number }> {
  if (process.platform === "darwin") return lsofConnections(pids);
  const inodes = new Set<string>();
  for (const pid of pids) {
    try {
      for (const fd of readdirSync(`/proc/${pid}/fd`)) {
        try {
          const m = /^socket:\[(\d+)\]$/.exec(readlinkSync(`/proc/${pid}/fd/${fd}`));
          if (m) inodes.add(m[1]!);
        } catch {
          /* closed meanwhile */
        }
      }
    } catch {
      /* gone, or not ours to read */
    }
  }
  if (!inodes.size) return [];
  const out = new Map<string, { ip: string; port: number }>();
  for (const [file, decode] of [["/proc/net/tcp", hexIp4], ["/proc/net/tcp6", hexIp6]] as const) {
    let text = "";
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    for (const line of text.split("\n").slice(1)) {
      const f = line.trim().split(/\s+/);
      if (f.length < 10 || f[3] !== "01" || !inodes.has(f[9]!)) continue; // 01 = established
      const [hexAddr, hexPort] = f[2]!.split(":");
      const ip = decode(hexAddr!);
      if (ip.startsWith("127.") || ip === "0:0:0:0:0:0:0:1") continue;
      const port = parseInt(hexPort!, 16);
      out.set(`${ip}:${port}`, { ip, port });
    }
  }
  return [...out.values()];
}

/** The command line of a process (for the activity of a free plugin). */
function commandOf(pid: number): string | undefined {
  if (process.platform === "darwin") return psTable().find((r) => r.pid === pid)?.command;
  try {
    return readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").filter(Boolean).join(" ").slice(0, 300);
  } catch {
    return undefined;
  }
}

/** What a free plugin's process was seen doing, outside its calls to the core. */
export type Observation = { kind: "connection"; ip: string; port: number } | { kind: "process"; command: string };

/** CPU time a process tree has used, in ms (Linux /proc); undefined where it cannot be read. */
function cpuMs(pid: number): number | undefined {
  if (process.platform === "darwin") {
    const rows = psTable();
    const tree = treeOf(rows, pid);
    const mine = rows.filter((r) => tree.includes(r.pid));
    return mine.length ? mine.reduce((t, r) => t + r.cpuMs, 0) : undefined;
  }
  let total = 0;
  let read = false;
  for (const p of processTree(pid)) {
    try {
      const stat = readFileSync(`/proc/${p}/stat`, "utf8");
      const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      const ticks = Number(fields[11]) + Number(fields[12]);
      if (Number.isFinite(ticks)) {
        total += ticks * 10;
        read = true;
      }
    } catch {
      /* gone meanwhile */
    }
  }
  return read ? total : undefined;
}

class CallFailure extends Error {
  constructor(
    message: string,
    readonly pluginTimeout = false,
  ) {
    super(message);
    this.name = "PluginCodeError";
  }
}

interface PendingCall {
  child: ChildProcess;
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
  onStep: (step: unknown) => Promise<unknown>;
  steps: number;
  timer: ReturnType<typeof setTimeout>;
}

const MARK = "\u0001P ";

export interface CodeProcessOptions {
  plugin: LoadedPlugin;
  hostDir: string;
  onLog?: (text: string) => void;
  onCrash?: (detail: string) => void;
  /** Use the kernel sandbox when the system has one (default true; tests may turn it off). */
  kernel?: boolean;
  /**
   * Code nobody reviewed yet (a draft in the sandbox): a free (Python) plugin runs inside the
   * kernel's sandbox anyway - no network, files read-only but its folder and /tmp. Refused where
   * the machine cannot do it.
   */
  contain?: boolean;
  limits?: Partial<CodeLimits>;
  /** Free plugins: environment that sends their traffic through Penteos's egress proxy. */
  egressEnv?: () => Record<string, string>;
  /** Free plugins: what the watcher sees (connections around the proxy, programs it starts). */
  onObserve?: (o: Observation) => void;
}

export class CodePluginProcess {
  private child: ChildProcess | undefined;
  private starting: Promise<string[]> | undefined;
  private readonly calls = new Map<number, PendingCall>();
  private seq = 0;
  private stopped = false;
  private lastUsed = Date.now();
  private watchdog: ReturnType<typeof setInterval> | undefined;
  readonly isolation: Isolation;
  readonly limits: CodeLimits;
  /** The memory ceiling the kernel enforces on it (MB), once started; undefined if none could be set. */
  memoryCeilingMb: number | undefined;

  constructor(private readonly options: CodeProcessOptions) {
    this.isolation = options.plugin.trust !== "isolated" ? "free" : options.kernel !== false && offlineSandbox() ? "kernel" : "process";
    this.limits = { ...CODE_LIMITS, ...(options.limits ?? {}) };
  }

  get pluginId(): string {
    return this.options.plugin.id;
  }

  /** The entry file, resolved inside the plugin folder (never outside it, never through a link). */
  private mainFile(): string {
    const dir = realpathSync(this.options.plugin.dir);
    const main = this.options.plugin.manifest.main;
    if (!main) throw new Error("a code plugin needs main");
    const file = resolve(dir, main);
    if (!file.startsWith(dir + sep) || !existsSync(file) || realpathSync(file) !== file) throw new Error(`main ${main} is not a file inside the plugin folder`);
    return file;
  }

  /** Starts the process (if not running) and resolves with the handlers its code registered. */
  start(): Promise<string[]> {
    if (this.starting) return this.starting;
    this.stopped = false;
    this.makeRoom();
    this.starting = new Promise<string[]>((resolveStart, rejectStart) => {
      let main: string;
      try {
        main = this.mainFile();
      } catch (e) {
        rejectStart(e);
        return;
      }
      const L = this.limits;
      const free = this.isolation === "free";
      const python = this.options.plugin.manifest.runtime === "python";
      if (python && !free) {
        rejectStart(new Error("a Python plugin runs only free"));
        return;
      }
      if (python && spawnSync("python3", ["--version"], { stdio: "ignore" }).status !== 0) {
        rejectStart(new Error("python3 is not installed on this machine"));
        return;
      }
      // Real paths: on macOS the temporary and some home folders sit behind links (/var is
      // /private/var), and Node's permission model checks the real path, so a grant on the linked
      // one would refuse the plugin its own files.
      const runner = realpathSync(python ? pythonRunnerFile(this.options.hostDir) : runnerFile(this.options.hostDir));
      const dir = realpathSync(this.options.plugin.dir);
      const node = python
        ? ["python3", "-u", "-B", runner, main]
        : free
          ? [process.execPath, runner, main]
          : [process.execPath, "--permission", `--allow-fs-read=${runner}`, `--allow-fs-read=${dir}`, `--max-old-space-size=${L.heapMb}`, "--disable-proto=throw", runner, main];
      const sandbox = this.isolation === "kernel" || (this.options.contain && free) ? offlineSandbox() : undefined;
      if (this.options.contain && free && !sandbox) {
        rejectStart(new Error("this machine cannot contain code nobody reviewed yet (install bubblewrap, or allow user namespaces for unshare)"));
        return;
      }
      const inner = sandbox ? sandbox.wrap(node[0]!, node.slice(1), dir) : { command: node[0]!, args: node.slice(1) };
      // The kernel's ceiling on its memory (any Linux: sh and ulimit): tight when isolated, wide when
      // free - it does not limit what a free plugin does, it keeps a runaway one from taking the machine.
      // macOS does not enforce ulimit -d: there the ceiling is kept by the watchdog from the
      // processes' resident memory instead (startWatchdog).
      const darwin = process.platform === "darwin";
      const ceiling = darwin ? undefined : python ? memoryCeiling("python3", L.freeMemoryMb, ["-c", "0"]) : memoryCeiling(process.execPath, free ? L.freeMemoryMb : L.memoryMb);
      this.memoryCeilingMb = darwin ? (python || free ? L.freeMemoryMb : L.memoryMb) : ceiling;
      // Through sh: the kernel's memory ceiling, and a low CPU priority the plugin itself inherits.
      const shell = process.platform === "linux" || process.platform === "darwin";
      const prelude = `${ceiling ? `ulimit -d ${ceiling * 1024}; ` : ""}command -v nice >/dev/null 2>&1 && exec nice -n 10 "$@"; exec "$@"`;
      const cmd = shell ? { command: "/bin/sh", args: ["-c", prelude, "penteos-plugin", inner.command, ...inner.args] } : inner;
      // A clean environment: nothing of the operator's (API keys, tokens) reaches the plugin.
      // Isolated: a clean environment. Free: the user's usual one (PATH, HOME…) with Penteos's egress
      // proxy, but never the operator's API keys (a plugin asks for its own in its settings).
      const env = free
        ? {
            ...pickEnv(["PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "SHELL", "TERM", "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "PYTHONPATH", "VIRTUAL_ENV"]),
            ELECTRON_RUN_AS_NODE: "1",
            PENTEOS_PLUGIN_FREE: "1",
            PENTEOS_PLUGIN_ID: this.options.plugin.id,
            PENTEOS_PLUGIN_DIR: dir,
            PYTHONUNBUFFERED: "1",
            // Python never writes nor reads bytecode in the plugin's folder: a cache there would change
            // its approved fingerprint, and a planted .pyc could run instead of the reviewed source.
            PYTHONDONTWRITEBYTECODE: "1",
            PYTHONPYCACHEPREFIX: join(this.options.hostDir, "pycache", this.options.plugin.id),
            ...(this.options.egressEnv?.() ?? {}),
          }
        : { ELECTRON_RUN_AS_NODE: "1", LANG: "C.UTF-8", PATH: "/usr/bin:/bin" };
      const child = spawn(cmd.command, cmd.args, { cwd: dir, env, stdio: ["pipe", "pipe", "pipe"] });
      this.child = child;
      running.add(this);
      if (!shell) {
        try {
          if (child.pid) setPriority(child.pid, 10); // below the interface, always
        } catch {
          /* not allowed here: it runs at normal priority */
        }
      }
      let stderr = "";
      child.stderr?.on("data", (d: Buffer) => {
        stderr = (stderr + String(d)).slice(-4000);
      });
      let buffer = "";
      let windowStart = Date.now();
      let windowCount = 0;
      child.stdout?.setEncoding("utf8");
      child.stdout?.on("data", (chunk: string) => {
        buffer += chunk;
        if (buffer.length > L.messageBytes && !buffer.includes("\n")) return this.end(`it sent a message larger than ${Math.round(L.messageBytes / 1048576)} MB`);
        let nl;
        while ((nl = buffer.indexOf("\n")) >= 0) {
          const line = buffer.slice(0, nl);
          buffer = buffer.slice(nl + 1);
          if (line.length > L.messageBytes) return this.end(`it sent a message larger than ${Math.round(L.messageBytes / 1048576)} MB`);
          if (Date.now() - windowStart > L.windowMs) {
            windowStart = Date.now();
            windowCount = 0;
          }
          if (++windowCount > L.messagesPerWindow) return this.end(`it sent more than ${L.messagesPerWindow} messages in ${L.windowMs / 1000} s`);
          if (!line.startsWith(MARK)) continue;
          let m: { type?: string; [k: string]: unknown };
          try {
            m = JSON.parse(line.slice(MARK.length)) as typeof m;
          } catch {
            continue;
          }
          if (m.type === "ready") {
            clearTimeout(timer);
            resolveStart(Array.isArray(m.handlers) ? (m.handlers as unknown[]).map(String) : []);
          } else if (m.type === "fatal") {
            clearTimeout(timer);
            rejectStart(new Error(String(m.error)));
          } else if (m.type === "log") {
            this.options.onLog?.(String(m.text));
          } else if (m.type === "return") {
            this.settle(Number(m.id), Boolean(m.ok), m.value, String(m.error ?? ""));
          } else if (m.type === "rpc") {
            void this.answer(Number(m.id), Number(m.callId), m.step);
          }
        }
      });
      const timer = setTimeout(() => {
        this.end(`it did not start within ${L.activationMs / 1000} s`);
        rejectStart(new Error(`it did not start within ${L.activationMs / 1000} s`));
      }, L.activationMs);
      child.on("exit", (code, signal) => {
        clearTimeout(timer);
        const current = this.child === child;
        const endedFor = this.endedFor.get(child);
        if (current) {
          this.child = undefined;
          this.starting = undefined;
          this.stopWatchdog();
          running.delete(this);
        }
        const oom = /heap out of memory|Allocation failed|Failed to allocate|Cannot allocate memory/i.test(stderr);
        const detail = endedFor ?? (oom ? `out of memory (over ${this.memoryCeilingMb ?? L.memoryMb} MB)` : `exited (${signal ?? code})${stderr ? `: ${stderr.trim().split("\n").slice(-2).join(" ").slice(0, 300)}` : ""}`);
        rejectStart(new Error(detail));
        // Only this process's calls fail with it (a new one may already be serving others).
        for (const [id, call] of this.calls) {
          if (call.child !== child) continue;
          clearTimeout(call.timer);
          call.reject(new CallFailure(`its process ${detail}`));
          this.calls.delete(id);
        }
        // Dying on its own, or ended for misbehaving, is a crash; stopped by us, idle or timed out is not.
        const benign = this.stopped || endedFor?.startsWith("no answer") || endedFor === "stopped after being idle";
        if ((current || endedFor) && !benign) this.options.onCrash?.(detail);
      });
      this.startWatchdog(child);
    });
    // A failed start can be tried again by the next call.
    this.starting.catch(() => {
      this.starting = undefined;
    });
    return this.starting;
  }

  /** Why each process the core ended was ended (its exit is reported as that, not as a crash). */
  private readonly endedFor = new WeakMap<ChildProcess, string>();

  /** Ends the current process for a reason; it is let go at once, so the next call starts a new one. */
  private end(reason: string): void {
    const child = this.child;
    if (!child) return;
    if (!this.endedFor.has(child)) this.endedFor.set(child, reason);
    this.child = undefined;
    this.starting = undefined;
    this.stopWatchdog();
    running.delete(this);
    child.kill("SIGKILL");
  }

  /** Busy with nobody calling it, or idle for long: either way it goes. */
  private startWatchdog(child: ChildProcess): void {
    this.stopWatchdog();
    let last = child.pid ? cpuMs(child.pid) : undefined;
    let busy = 0;
    const seenConnections = new Set<string>();
    const seenPids = new Set<number>();
    let tick = 0;
    this.watchdog = setInterval(() => {
      tick++;
      if (this.child !== child || !child.pid) return this.stopWatchdog();
      if (this.calls.size === 0 && Date.now() - this.lastUsed > this.limits.idleStopMs) return this.end("stopped after being idle");
      // A free plugin is watched, not limited: what it connects to and what it starts.
      if (this.isolation === "free" && this.options.onObserve) {
        const tree = processTree(child.pid);
        // lsof (macOS) is slower than reading /proc: every third sample is enough to see a connection.
        for (const c of process.platform !== "darwin" || tick % 3 === 1 ? connectionsOf(tree) : []) {
          const key = `${c.ip}:${c.port}`;
          if (seenConnections.has(key)) continue;
          seenConnections.add(key);
          this.options.onObserve({ kind: "connection", ...c });
        }
        for (const pid of tree.slice(1)) {
          if (seenPids.has(pid)) continue;
          seenPids.add(pid);
          const command = commandOf(pid);
          if (command) this.options.onObserve({ kind: "process", command });
        }
      }
      // macOS does not enforce ulimit -d: the memory ceiling is kept here, from the resident size.
      if (process.platform === "darwin" && this.memoryCeilingMb) {
        const rows = psTable();
        const tree = treeOf(rows, child.pid);
        const mb = rows.filter((r) => tree.includes(r.pid)).reduce((t, r) => t + r.rssKb, 0) / 1024;
        if (mb > this.memoryCeilingMb) return this.end(`it used more than ${this.memoryCeilingMb} MB of memory`);
      }
      const now = cpuMs(child.pid);
      if (now === undefined || last === undefined) return;
      const share = (now - last) / this.limits.sampleMs;
      last = now;
      busy = this.calls.size === 0 && share > this.limits.idleCpuShare ? busy + 1 : 0;
      if (busy >= this.limits.busySamples) this.end(`it kept the CPU busy (${Math.round(share * 100)}%) while nobody was calling it`);
    }, this.limits.sampleMs);
    this.watchdog.unref();
  }

  private stopWatchdog(): void {
    if (this.watchdog) clearInterval(this.watchdog);
    this.watchdog = undefined;
  }

  /** Too many plugin processes: the one idle the longest stops (it starts again when called). */
  private makeRoom(): void {
    if (running.size < MAX_CODE_PROCESSES) return;
    const idle = [...running].filter((p) => p !== this && p.calls.size === 0).sort((a, b) => a.lastUsed - b.lastUsed)[0];
    idle?.stop();
  }

  /**
   * Runs one handler; every request it makes to the core goes through onStep. A free plugin also
   * gets `output`, the project's folder for its files, to write there itself.
   */
  async call(handler: string, input: unknown, engagement: unknown, timeoutMs: number, onStep: (step: unknown) => Promise<unknown>, output?: string): Promise<unknown> {
    this.lastUsed = Date.now();
    await this.start();
    const child = this.child;
    if (!child) throw new CallFailure("its process is not running");
    const id = ++this.seq;
    return new Promise((resolveCall, rejectCall) => {
      const timer = setTimeout(() => {
        this.calls.delete(id);
        // A plugin that does not answer may be stuck in a loop: its process goes, the next call starts a new one.
        this.end(`no answer within ${timeoutMs} ms`);
        rejectCall(new CallFailure(`no answer within ${timeoutMs} ms (its process was stopped)`, true));
      }, timeoutMs);
      this.calls.set(id, { child, resolve: resolveCall, reject: rejectCall, onStep, steps: 0, timer });
      this.write({ type: "call", id, handler, input, engagement, ...(output && this.isolation === "free" ? { output } : {}) }, child);
    });
  }

  private write(msg: Record<string, unknown>, child = this.child): void {
    try {
      child?.stdin?.write(`${JSON.stringify(msg)}\n`);
    } catch {
      /* the process went away meanwhile */
    }
  }

  private settle(id: number, ok: boolean, value: unknown, error: string): void {
    const call = this.calls.get(id);
    if (!call) return;
    clearTimeout(call.timer);
    this.calls.delete(id);
    this.lastUsed = Date.now();
    if (ok) call.resolve(value);
    else call.reject(new CallFailure(error || "failed"));
  }

  private async answer(rpcId: number, callId: number, step: unknown): Promise<void> {
    const call = this.calls.get(callId);
    const reply = (msg: Record<string, unknown>) => this.write({ type: "rpc_result", id: rpcId, ...msg }, call?.child);
    if (!call) return reply({ ok: false, error: "that call is over" });
    if (++call.steps > this.limits.rpcPerCall) return reply({ ok: false, error: `more than ${this.limits.rpcPerCall} requests to the core in one call` });
    try {
      reply({ ok: true, value: (await call.onStep(step)) ?? null });
    } catch (e) {
      reply({ ok: false, error: (e instanceof Error ? e.message : String(e)).slice(0, 2000) });
    }
  }

  stop(): void {
    this.stopped = true;
    this.stopWatchdog();
    this.child?.kill("SIGKILL");
    this.child = undefined;
    this.starting = undefined;
    running.delete(this);
  }

  get running(): boolean {
    return Boolean(this.child);
  }
}

/**
 * Activates a code plugin: storage and types as a declarative one, then its process; every handler
 * the manifest names must be registered by its code, or it does not activate.
 */
export function codeActivator(
  data: PluginData,
  runtime: PluginRuntime,
  options: { hostDir: string; kernel?: boolean; contain?: boolean; limits?: Partial<CodeLimits>; onLog?: (id: string, text: string) => void; onCrash?: (id: string, detail: string) => void; egressEnv?: (id: string) => Record<string, string> },
): PluginActivator {
  return {
    async activate(plugin) {
      if ((plugin.manifest.contributes.storage?.global ?? []).length > 0) {
        try {
          data.openGlobal(plugin.id);
        } catch (e) {
          throw storageActivationError(e);
        }
      }
      const proc = new CodePluginProcess({
        plugin,
        hostDir: options.hostDir,
        ...(options.kernel !== undefined ? { kernel: options.kernel } : {}),
        ...(options.contain ? { contain: true } : {}),
        ...(options.limits ? { limits: options.limits } : {}),
        onLog: (t) => options.onLog?.(plugin.id, t),
        ...(options.egressEnv ? { egressEnv: () => options.egressEnv!(plugin.id) } : {}),
        onObserve: (o) => runtime.observe(plugin.id, o),
        onCrash: (d) => options.onCrash?.(plugin.id, d),
      });
      const registered = await proc.start();
      const wanted = [...(plugin.manifest.contributes.operations ?? []).map((o) => o.handler), ...(plugin.manifest.contributes.parsers ?? []).map((p) => p.handler), ...(plugin.manifest.contributes.proxy ?? []).map((h) => h.handler)].filter((h): h is string => Boolean(h));
      const missing = [...new Set(wanted)].filter((h) => !registered.includes(h));
      if (missing.length) {
        proc.stop();
        throw new Error(`its code does not register the handler${missing.length > 1 ? "s" : ""} ${missing.join(", ")}`);
      }
      data.types.register(plugin.id, plugin.manifest);
      try {
        runtime.register(plugin);
        runtime.attachCode(plugin.id, proc);
      } catch (e) {
        proc.stop();
        data.types.unregister(plugin.id);
        throw e;
      }
    },
    deactivate(id) {
      runtime.detachCode(id)?.stop();
      runtime.unregister(id);
      data.types.unregister(id);
      data.close(id);
    },
  };
}
