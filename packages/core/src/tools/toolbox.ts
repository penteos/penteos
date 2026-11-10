import { execFile, execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { closeSync, createReadStream, existsSync, mkdirSync, openSync, readFileSync, readSync, readdirSync, renameSync, rmSync, statSync, statfsSync, symlinkSync, unlinkSync, writeFileSync, writeSync, accessSync, constants, lstatSync } from "node:fs";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect as tlsConnect } from "node:tls";
import { join, relative } from "node:path";
import { readArchive } from "./archive.js";
import { CATALOG, currentPlatform, type CatalogAsset, type CatalogEntry, type Platform } from "./catalog.js";

/**
 * Penteos's own tool box: tools from the verified catalog, installed
 * in the user's data folder, without root, Docker or a compiler. An install is atomic: checked
 * first (space, a folder that can run programs, the catalog), downloaded with resume, verified
 * against the catalog's SHA-256, unpacked aside, run once to prove it is the tool, and only then
 * switched on with a rename. Whatever happens in between (a crash, a cut, a wrong file), no tool is
 * ever left half-installed and marked ready.
 *
 *   toolbox/
 *     bin/<tool>                 → link to the active version (the PATH tools get)
 *     pkgs/<tool>/<version>/     → each version apart, never overwritten in place
 *     downloads/<sha256>.part    → partial downloads, resumed
 *     state.json                 → what is installed and verified, its size, when it was last used
 */

export type ToolboxProblemCode =
  | "NOT_IN_CATALOG"
  | "NO_ASSET"
  | "NO_SPACE"
  | "QUOTA"
  | "NOEXEC"
  | "DOWNLOAD_FAILED"
  | "HASH_MISMATCH"
  | "BAD_ARCHIVE"
  | "IDENTITY_FAILED"
  | "CANCELLED";

/** Why an install did not happen, with what to do about it (shown to the operator and the agent). */
export class ToolboxError extends Error {
  constructor(
    readonly code: ToolboxProblemCode,
    message: string,
    readonly hint?: string,
  ) {
    super(message);
  }
}

export interface InstalledTool {
  name: string;
  version: string;
  /** Folder of this version, relative to the box. */
  dir: string;
  /** Executable, relative to the box. */
  binary: string;
  sha256: string;
  /** Bytes on disk once unpacked. */
  bytes: number;
  installedAt: string;
  lastUsedAt?: string;
  /** The version it replaced, kept until the next install so the operator can go back. */
  previous?: { version: string; dir: string; binary: string; sha256: string; bytes: number; installedAt: string };
}

interface State {
  tools: Record<string, InstalledTool>;
}

export interface InstallOptions {
  /** One line at a time, for the run's output ("descargando 34 %…"). */
  onProgress?: (line: string) => void;
  signal?: AbortSignal;
  /**
   * Proves the unpacked file is the tool (runs it with the manifest's identity arguments). Returns
   * an error message, or undefined when it is.
   */
  verify?: (binary: string) => Promise<string | undefined>;
}

export interface ToolboxOptions {
  catalog?: readonly CatalogEntry[];
  platform?: Platform;
  /** Most the box may hold (default 2 GB). */
  quotaBytes?: number;
  /** Tests only: let http:// URLs through and shorten the waits between retries. */
  allowHttp?: boolean;
  retryDelayMs?: number;
  /** How long a stalled connection is waited for. */
  idleTimeoutMs?: number;
  /** Tests only: the free space to assume (a full disk cannot be simulated safely otherwise). */
  freeSpace?: () => number | undefined;
  /** Tests only: whether a URL answers (no network in the suite). */
  reach?: (url: string) => Promise<boolean>;
}

export const DEFAULT_QUOTA = 2_000_000_000;

/** The running core's tool box, for code that finds a tool without the registry (the OOB listener). */
export const activeToolbox: { box?: Toolbox } = {};
/** Room needed for a download: the archive, its unpacked contents (Go binaries unpack to ~3×) and margin. */
const SPACE_FACTOR = 4;
const RETRIES = 4;

export class Toolbox {
  readonly binDir: string;
  private readonly pkgsDir: string;
  private readonly downloadsDir: string;
  private readonly stateFile: string;
  private readonly catalog: readonly CatalogEntry[];
  private readonly platform: Platform | undefined;
  private readonly quota: number;
  /** One install per tool at a time: a second request for the same tool waits for the first. */
  private readonly inflight = new Map<string, Promise<InstalledTool>>();
  /** And one install at a time overall, so two never compete for the same space. */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    readonly dir: string,
    private readonly options: ToolboxOptions = {},
  ) {
    this.binDir = join(dir, "bin");
    this.pkgsDir = join(dir, "pkgs");
    this.downloadsDir = join(dir, "downloads");
    this.stateFile = join(dir, "state.json");
    this.catalog = options.catalog ?? CATALOG;
    this.platform = options.platform ?? currentPlatform();
    this.quota = options.quotaBytes ?? DEFAULT_QUOTA;
    for (const d of [this.binDir, this.pkgsDir, this.downloadsDir]) mkdirSync(d, { recursive: true });
    this.recover();
  }

  // -------------------------------------------------------------------------------------------
  // What is there

  entry(name: string): CatalogEntry | undefined {
    return this.catalog.find((e) => e.name === name);
  }

  /**
   * What gets downloaded for a tool on this machine. A uv tool has no file of its own: uv (itself
   * from the catalog) builds it from its hash-locked packages, so its "asset" is that recipe.
   */
  asset(name: string): CatalogAsset | undefined {
    const e = this.entry(name);
    if (!e || !this.platform) return undefined;
    if (e.via === "uv") return e.uv && this.entry("uv")?.assets[this.platform] && (this.platform.startsWith("linux") || this.platform.startsWith("darwin")) ? { url: "uv", sha256: "", size: e.uv.size, format: "raw", bin: e.binary } : undefined;
    return e.assets[this.platform];
  }

  /** Tools the catalog offers for this machine. */
  available(): Array<{ entry: CatalogEntry; asset: CatalogAsset }> {
    return this.catalog.flatMap((entry) => {
      const asset = this.asset(entry.name);
      return asset ? [{ entry, asset }] : [];
    });
  }

  installed(): InstalledTool[] {
    return Object.values(this.state().tools);
  }

  get(name: string): InstalledTool | undefined {
    return this.state().tools[name];
  }

  /** The verified executable of a tool, if it is installed and still there. */
  binaryPath(name: string): string | undefined {
    const t = this.get(name);
    if (!t) return undefined;
    const path = join(this.dir, t.binary);
    try {
      accessSync(path, constants.X_OK);
      return path;
    } catch {
      return undefined;
    }
  }

  /** Environment a managed tool needs (where its data folder is), e.g. NMAPDIR for nmap. */
  envFor(name: string): Record<string, string> {
    const t = this.get(name);
    const asset = this.entry(name)?.assets[this.platform ?? "linux-x64"];
    if (!t || !asset?.data || !asset.dataEnv) return {};
    return { [asset.dataEnv]: join(this.dir, t.dir, "data") };
  }

  /** Environment of every managed tool, for the processes the runner starts. */
  env(): Record<string, string> {
    return Object.assign({}, ...this.installed().map((t) => this.envFor(t.name)));
  }

  /** Bytes the box takes on disk (installed versions, previous ones and partial downloads). */
  usage(): number {
    return dirSize(this.pkgsDir) + dirSize(this.downloadsDir) + dirSize(join(this.dir, "python"));
  }

  get quotaBytes(): number {
    return this.quota;
  }

  markUsed(name: string): void {
    const state = this.state();
    const t = state.tools[name];
    if (!t) return;
    t.lastUsedAt = new Date().toISOString();
    this.save(state);
  }

  // -------------------------------------------------------------------------------------------
  // Before downloading

  /**
   * Everything that can be known before a byte is downloaded: the catalog has the tool for this
   * machine, there is room (on disk and within the box's limit), and the folder can run programs
   * (some hardened systems mount /home with noexec).
   */
  preflight(name: string): { entry: CatalogEntry; asset: CatalogAsset } {
    const entry = this.entry(name);
    if (!entry) throw new ToolboxError("NOT_IN_CATALOG", `${name} is not in Penteos's verified catalog`, "Install it with your system's package manager, or add a manifest for it.");
    const asset = this.asset(name);
    if (!asset) throw new ToolboxError("NO_ASSET", `the catalog has no ${name} for this system (${this.platform ?? "unknown platform"})`, "Install it with your system's package manager.");
    const need = Math.ceil(asset.size * SPACE_FACTOR);
    const free = this.options.freeSpace ? this.options.freeSpace() : freeBytes(this.dir);
    if (free !== undefined && free < need) {
      throw new ToolboxError("NO_SPACE", `not enough free space for ${name}: it needs ${mb(need)} and there are ${mb(free)} free in ${this.dir}`, "Free some space (the Tools panel can remove tools you do not use) and try again.");
    }
    const current = this.get(name);
    const after = this.usage() - (current?.previous?.bytes ?? 0) + need;
    if (after > this.quota) {
      throw new ToolboxError("QUOTA", `installing ${name} would take the tool box past its limit of ${mb(this.quota)} (${mb(after)})`, "Remove tools you do not use from the Tools panel, or raise the limit.");
    }
    this.checkCanExecute();
    return { entry, asset };
  }

  private checkCanExecute(): void {
    const probe = join(this.dir, `.probe-${randomBytes(4).toString("hex")}`);
    try {
      writeFileSync(probe, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
      const ok = (() => {
        try {
          accessSync(probe, constants.X_OK);
          return true;
        } catch {
          return false;
        }
      })();
      if (!ok || !runsSync(probe)) {
        throw new ToolboxError("NOEXEC", `programs cannot run from ${this.dir} (the folder is mounted noexec)`, "Choose another folder for Penteos's data (PENTEOS_DATA_DIR), one on a partition that allows running programs.");
      }
    } finally {
      rmSync(probe, { force: true });
    }
  }

  // -------------------------------------------------------------------------------------------
  // Installing

  install(name: string, options: InstallOptions = {}): Promise<InstalledTool> {
    const running = this.inflight.get(name);
    if (running) return running;
    const job = this.queue.then(() => this.doInstall(name, options));
    const tracked = job.finally(() => this.inflight.delete(name));
    this.inflight.set(name, tracked);
    // The queue moves on whatever the outcome.
    this.queue = tracked.catch(() => undefined);
    return tracked;
  }

  private async doInstall(name: string, options: InstallOptions): Promise<InstalledTool> {
    const say = options.onProgress ?? (() => {});
    const { entry, asset } = this.preflight(name);
    if (entry.via === "uv") return this.installWithUv(entry, options);
    say(`${name} ${entry.version} · ${mb(asset.size)} · ${asset.url}`);
    const file = await this.download(asset, options);
    say("SHA-256 verified");

    // Unpacked aside: nothing in pkgs/<tool>/<version> until it is proven.
    const toolDir = join(this.pkgsDir, name);
    mkdirSync(toolDir, { recursive: true });
    const staging = join(toolDir, `.tmp-${randomBytes(4).toString("hex")}`);
    try {
      let files;
      try {
        files = readArchive(readFileSync(file), asset.format, asset.bin);
      } catch (e) {
        rmSync(file, { force: true });
        throw new ToolboxError("BAD_ARCHIVE", `the ${name} download could not be unpacked: ${(e as Error).message}`);
      }
      const bin = files.find((f) => f.path === asset.bin);
      if (!bin) throw new ToolboxError("BAD_ARCHIVE", `${asset.bin} is not inside the ${name} download`);
      mkdirSync(staging, { recursive: true });
      const binaryName = entry.binary + (this.platform?.startsWith("win32") ? ".exe" : "");
      // Only the executable is kept (release archives add a README and a license we link instead),
      // plus the data folder a tool needs, when it has one (nmap's scripts and fingerprints).
      writeFileSync(join(staging, binaryName), bin.data, { mode: 0o755 });
      if (asset.data) {
        const prefix = `${asset.data.replace(/\/+$/, "")}/`;
        for (const f of files.filter((x) => x.path.startsWith(prefix))) {
          const to = join(staging, "data", f.path.slice(prefix.length));
          mkdirSync(join(to, ".."), { recursive: true });
          writeFileSync(to, f.data, { mode: f.executable ? 0o755 : 0o644 });
        }
      }
      say("unpacked");

      if (options.verify) {
        const problem = await options.verify(join(staging, binaryName));
        if (problem) throw new ToolboxError("IDENTITY_FAILED", `the downloaded ${name} does not run here: ${problem}`, "This system may be missing something it needs; the Tools panel says what.");
      }
      say("ran and answered as " + name);
      if (options.signal?.aborted) throw new ToolboxError("CANCELLED", "install cancelled");

      // Switched on: the version folder (rename), then the link (rename over the old one), then the state.
      const versionDir = join(toolDir, entry.version);
      rmSync(versionDir, { recursive: true, force: true });
      renameSync(staging, versionDir);
      const linkTarget = join(versionDir, binaryName);
      const tmpLink = join(this.binDir, `.tmp-${name}-${randomBytes(4).toString("hex")}`);
      symlinkSync(relative(this.binDir, linkTarget), tmpLink);
      renameSync(tmpLink, join(this.binDir, binaryName));

      const state = this.state();
      const before = state.tools[name];
      const installed: InstalledTool = {
        name,
        version: entry.version,
        dir: relative(this.dir, versionDir),
        binary: relative(this.dir, linkTarget),
        sha256: asset.sha256,
        bytes: dirSize(versionDir),
        installedAt: new Date().toISOString(),
        ...(before && before.version !== entry.version ? { previous: { version: before.version, dir: before.dir, binary: before.binary, sha256: before.sha256, bytes: before.bytes, installedAt: before.installedAt } } : before?.previous ? { previous: before.previous } : {}),
      };
      // Two versions at most: the one before the previous goes.
      if (before?.previous && before.version !== entry.version && before.previous.dir !== installed.dir) rmSync(join(this.dir, before.previous.dir), { recursive: true, force: true });
      state.tools[name] = installed;
      this.save(state);
      rmSync(file, { force: true });
      say(`done: ${name} ${entry.version}`);
      return installed;
    } finally {
      rmSync(staging, { recursive: true, force: true });
    }
  }

  /**
   * A Python tool: uv (from the catalog, verified like any other)
   * makes an environment with its own Python, installs the hash-locked packages (any package whose
   * hash differs is refused), the tool proves it runs, and only then the environment is moved into
   * place and linked. The environment is relocatable, so building it aside costs nothing.
   */
  private async installWithUv(entry: CatalogEntry, options: InstallOptions): Promise<InstalledTool> {
    const say = options.onProgress ?? (() => {});
    const spec = entry.uv!;
    if (!this.binaryPath("uv")) {
      say("uv first, which installs the Python tools");
      await this.doInstall("uv", { ...options, verify: undefined });
    }
    const uv = this.binaryPath("uv")!;
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      UV_PYTHON_INSTALL_DIR: join(this.dir, "python"),
      UV_CACHE_DIR: join(this.dir, "cache", "uv"),
      UV_NO_CONFIG: "1",
      UV_PYTHON_PREFERENCE: "only-managed",
      NO_COLOR: "1",
    };
    const toolDir = join(this.pkgsDir, entry.name);
    mkdirSync(toolDir, { recursive: true });
    const staging = join(toolDir, `.tmp-${randomBytes(4).toString("hex")}`);
    const binaryName = entry.binary;
    try {
      mkdirSync(staging, { recursive: true });
      say(`Penteos's own Python ${spec.python} (downloaded once for all the Python tools)`);
      await runUv(uv, ["venv", "--quiet", "--relocatable", "--python", spec.python, join(staging, "venv")], env, say, options.signal);
      writeFileSync(join(staging, "requirements.txt"), spec.lock);
      say(`${entry.name} ${entry.version}: packages with verified hashes`);
      await runUv(uv, ["pip", "install", "--quiet", "--python", join(staging, "venv", "bin", "python"), "--require-hashes", "-r", join(staging, "requirements.txt")], env, say, options.signal);
      const bin = join(staging, "venv", "bin", binaryName);
      if (!existsSync(bin)) throw new ToolboxError("BAD_ARCHIVE", `${entry.name} installed but ${binaryName} is not in its environment`);
      if (options.verify) {
        const problem = await options.verify(bin);
        if (problem) throw new ToolboxError("IDENTITY_FAILED", `the installed ${entry.name} does not run here: ${problem}`);
      }
      say("ran and answered as " + entry.name);
      if (options.signal?.aborted) throw new ToolboxError("CANCELLED", "install cancelled");
      const versionDir = join(toolDir, entry.version);
      rmSync(versionDir, { recursive: true, force: true });
      renameSync(staging, versionDir);
      const linkTarget = join(versionDir, "venv", "bin", binaryName);
      const tmpLink = join(this.binDir, `.tmp-${entry.name}-${randomBytes(4).toString("hex")}`);
      symlinkSync(relative(this.binDir, linkTarget), tmpLink);
      renameSync(tmpLink, join(this.binDir, binaryName));
      const state = this.state();
      const before = state.tools[entry.name];
      const installed: InstalledTool = {
        name: entry.name,
        version: entry.version,
        dir: relative(this.dir, versionDir),
        binary: relative(this.dir, linkTarget),
        sha256: createHash("sha256").update(spec.lock).digest("hex"),
        bytes: dirSize(versionDir),
        installedAt: new Date().toISOString(),
        ...(before && before.version !== entry.version ? { previous: { version: before.version, dir: before.dir, binary: before.binary, sha256: before.sha256, bytes: before.bytes, installedAt: before.installedAt } } : {}),
      };
      state.tools[entry.name] = installed;
      this.save(state);
      say(`done: ${entry.name} ${entry.version}`);
      return installed;
    } finally {
      rmSync(staging, { recursive: true, force: true });
      // The package cache only served this install: the space goes back.
      rmSync(join(this.dir, "cache", "uv"), { recursive: true, force: true });
    }
  }

  // -------------------------------------------------------------------------------------------
  // Diagnosis: what could keep an install from working, with its fix

  /** Whether a host answers over HTTPS from here (through HTTPS_PROXY when set). */
  reach(url: string, timeoutMs = 6000): Promise<boolean> {
    if (this.options.reach) return this.options.reach(url);
    return new Promise((resolve) => {
      try {
        const u = new URL(url);
        const req = this.requestVia(u, { "user-agent": "Penteos" }, (res) => {
          res.resume();
          resolve((res.statusCode ?? 0) > 0);
        }, () => resolve(false));
        req.setTimeout(timeoutMs, () => req.destroy(new Error("timeout")));
        req.end();
      } catch {
        resolve(false);
      }
    });
  }

  async diagnose(): Promise<Array<{ id: string; ok: boolean; level: "error" | "warn" | "info"; detail?: string }>> {
    const out: Array<{ id: string; ok: boolean; level: "error" | "warn" | "info"; detail?: string }> = [];
    try {
      this.checkCanExecute();
      out.push({ id: "exec", ok: true, level: "error" });
    } catch (e) {
      out.push({ id: "exec", ok: false, level: "error", detail: (e as Error).message });
    }
    const free = this.options.freeSpace ? this.options.freeSpace() : freeBytes(this.dir);
    out.push({ id: "space", ok: free === undefined || free > 500e6, level: "warn", ...(free !== undefined ? { detail: mb(free) } : {}) });
    const [github, nmap, pypi] = await Promise.all([this.reach("https://github.com/"), this.reach("https://nmap.org/"), this.reach("https://pypi.org/")]);
    out.push({ id: "net.github", ok: github, level: "warn" }, { id: "net.nmap", ok: nmap, level: "info" }, { id: "net.pypi", ok: pypi, level: "info" });
    const unpack = ["xz", "python3"].some((b) => {
      try {
        execFileSync(b, ["--version"], { stdio: "ignore", timeout: 5000 });
        return true;
      } catch {
        return false;
      }
    });
    if (this.platform === "linux-x64") out.push({ id: "xz", ok: unpack, level: "info" });
    return out;
  }

  // -------------------------------------------------------------------------------------------
  // A kit for networks without internet

  /**
   * Writes the catalog's tools for a platform into one file to carry to a network without
   * internet: each downloaded and verified here first, then stored as is next to a manifest.
   * Python tools (uv) are not included yet: they need Python and their packages.
   */
  async exportKit(dest: string, options: InstallOptions & { platform?: Platform; names?: string[] } = {}): Promise<{ file: string; tools: Array<{ name: string; version: string; size: number }> }> {
    const say = options.onProgress ?? (() => {});
    const platform = options.platform ?? this.platform;
    if (!platform) throw new ToolboxError("NO_ASSET", "unknown platform");
    const chosen = this.catalog.filter((e) => e.via === "release" && e.assets[platform] && (!options.names?.length || options.names.includes(e.name)));
    if (!chosen.length) throw new ToolboxError("NOT_IN_CATALOG", "nothing in the catalog for that platform");
    const need = chosen.reduce((n, e) => n + e.assets[platform]!.size, 0) * 2.2;
    const free = this.options.freeSpace ? this.options.freeSpace() : freeBytes(this.dir);
    if (free !== undefined && free < need) throw new ToolboxError("NO_SPACE", `the kit needs about ${mb(need)} free and there are ${mb(free)}`);
    const tmp = `${dest}.${randomBytes(4).toString("hex")}.tmp`;
    const fd = openSync(tmp, "w");
    const tools: Array<{ name: string; version: string; size: number; sha256: string; file: string }> = [];
    try {
      const parts: string[] = [];
      for (const e of chosen) {
        const asset = e.assets[platform]!;
        say(`${e.name} ${e.version} (${mb(asset.size)})`);
        parts.push(await this.download(asset, { ...options, onProgress: () => {} }));
        tools.push({ name: e.name, version: e.version, size: asset.size, sha256: asset.sha256, file: `${e.name}-${e.version}-${platform}.${asset.format === "tar.gz" ? "tar.gz" : asset.format}` });
      }
      const manifest = Buffer.from(JSON.stringify({ format: "penteos-tools/1", platform, createdAt: new Date().toISOString(), tools }, null, 2));
      writeTarEntry(fd, "manifest.json", manifest);
      tools.forEach((t, i) => writeTarEntry(fd, t.file, readFileSync(parts[i]!)));
      writeSync(fd, Buffer.alloc(1024));
      closeSync(fd);
      renameSync(tmp, dest);
      for (const p of parts) rmSync(p, { force: true });
      say(`kit ready: ${tools.length} tools, ${mb(statSync(dest).size)}`);
      return { file: dest, tools: tools.map(({ name, version, size }) => ({ name, version, size })) };
    } catch (e) {
      try {
        closeSync(fd);
      } catch {
        /* closed */
      }
      rmSync(tmp, { force: true });
      throw e;
    }
  }

  /**
   * Installs the tools of a kit without internet. Every file is checked against THIS Penteos's
   * catalog (never against the kit's own list): a file the catalog does not know, or whose hash
   * differs, is left out and said so.
   */
  async importKit(file: string, options: InstallOptions = {}): Promise<{ installed: InstalledTool[]; skipped: Array<{ file: string; reason: string }> }> {
    const say = options.onProgress ?? (() => {});
    const skipped: Array<{ file: string; reason: string }> = [];
    const toInstall: string[] = [];
    let platform: string | undefined;
    const fd = openSync(file, "r");
    try {
      let off = 0;
      const header = Buffer.alloc(512);
      while (readSync(fd, header, 0, 512, off) === 512 && !header.every((b) => b === 0)) {
        const name = header.subarray(0, 100).toString("utf8").replace(/\0.*$/s, "");
        const size = parseInt(header.subarray(124, 136).toString("utf8").replace(/\0.*$/s, "").trim() || "0", 8);
        const body = Buffer.alloc(size);
        readSync(fd, body, 0, size, off + 512);
        off += 512 + Math.ceil(size / 512) * 512;
        if (name === "manifest.json") {
          platform = (JSON.parse(body.toString("utf8")) as { platform?: string }).platform;
          if (platform && platform !== this.platform) throw new ToolboxError("NO_ASSET", `this kit is for ${platform} and this machine is ${this.platform}`);
          continue;
        }
        const sha = createHash("sha256").update(body).digest("hex");
        const entry = this.catalog.find((e) => this.platform && e.assets[this.platform]?.sha256 === sha);
        if (!entry) {
          skipped.push({ file: name, reason: "not in this Penteos's verified catalog (another version, or altered)" });
          say(`${name}: does not match the verified catalog; left out`);
          continue;
        }
        writeFileSync(join(this.downloadsDir, `${sha}.part`), body);
        toInstall.push(entry.name);
      }
    } finally {
      closeSync(fd);
    }
    const installed: InstalledTool[] = [];
    for (const name of toInstall) {
      say(`installing ${name} from the kit`);
      installed.push(await this.install(name, options));
    }
    return { installed, skipped };
  }

  /** Back to the version before the last install (kept for this). */
  rollback(name: string): InstalledTool {
    const state = this.state();
    const t = state.tools[name];
    if (!t?.previous) throw new ToolboxError("NOT_IN_CATALOG", `${name} has no previous version to go back to`);
    const prev = t.previous;
    if (!existsSync(join(this.dir, prev.binary))) throw new ToolboxError("NOT_IN_CATALOG", `the previous ${name} (${prev.version}) is no longer on disk`);
    const tmpLink = join(this.binDir, `.tmp-${name}-${randomBytes(4).toString("hex")}`);
    const linkName = join(this.binDir, prev.binary.split("/").pop()!);
    symlinkSync(relative(this.binDir, join(this.dir, prev.binary)), tmpLink);
    renameSync(tmpLink, linkName);
    const back: InstalledTool = { name, ...prev, previous: { version: t.version, dir: t.dir, binary: t.binary, sha256: t.sha256, bytes: t.bytes, installedAt: t.installedAt } };
    state.tools[name] = back;
    this.save(state);
    return back;
  }

  /** Removes a tool and every version of it. */
  remove(name: string): { freed: number } {
    const state = this.state();
    const t = state.tools[name];
    const toolDir = join(this.pkgsDir, name);
    const freed = dirSize(toolDir);
    if (t) {
      for (const link of [t.binary, t.previous?.binary]) {
        if (!link) continue;
        const l = join(this.binDir, link.split("/").pop()!);
        try {
          if (lstatSync(l).isSymbolicLink()) unlinkSync(l);
        } catch {
          /* already gone */
        }
      }
      delete state.tools[name];
      this.save(state);
    }
    rmSync(toolDir, { recursive: true, force: true });
    // Python (shared by the uv tools) goes with the last of them.
    const pyDir = join(this.dir, "python");
    if (!Object.keys(state.tools).some((n) => this.entry(n)?.via === "uv") && existsSync(pyDir)) {
      const py = dirSize(pyDir);
      rmSync(pyDir, { recursive: true, force: true });
      return { freed: freed + py };
    }
    return { freed };
  }

  // -------------------------------------------------------------------------------------------
  // Downloading

  /**
   * Downloads to downloads/<sha256>.part and returns the verified file. Resumes what is already
   * there (Range), retries cuts with growing waits, and checks the whole file's SHA-256 at the end:
   * a file that does not match is deleted and never retried as is.
   */
  private async download(asset: CatalogAsset, options: InstallOptions): Promise<string> {
    const say = options.onProgress ?? (() => {});
    const part = join(this.downloadsDir, `${asset.sha256}.part`);
    let lastError: Error | undefined;
    for (let attempt = 0; attempt <= RETRIES; attempt++) {
      if (options.signal?.aborted) throw new ToolboxError("CANCELLED", "install cancelled");
      if (attempt > 0) {
        const wait = (this.options.retryDelayMs ?? 1000) * 2 ** (attempt - 1);
        say(`retry ${attempt}/${RETRIES} in ${Math.round(wait / 1000)} s (${lastError?.message ?? ""})`);
        await sleep(wait, options.signal);
      }
      const have = existsSync(part) ? statSync(part).size : 0;
      if (have > asset.size) rmSync(part, { force: true });
      if (have === asset.size) break;
      try {
        await this.fetchTo(asset.url, part, existsSync(part) ? statSync(part).size : 0, asset.size, say, options.signal);
        if (statSync(part).size >= asset.size) break;
        lastError = new Error("the connection ended before the whole file arrived");
      } catch (e) {
        if (e instanceof ToolboxError) throw e;
        lastError = e as Error;
      }
    }
    if (!existsSync(part) || statSync(part).size !== asset.size) {
      throw new ToolboxError("DOWNLOAD_FAILED", `could not download ${asset.url}: ${lastError?.message ?? "incomplete"}`, "Check the connection (or HTTPS_PROXY behind a corporate proxy) and try again; the download resumes where it stopped.");
    }
    const sha = await sha256File(part);
    if (sha !== asset.sha256) {
      rmSync(part, { force: true });
      throw new ToolboxError("HASH_MISMATCH", `the downloaded file does not match the catalog (SHA-256 ${sha.slice(0, 12)}…, expected ${asset.sha256.slice(0, 12)}…); it was deleted and not installed`, "Someone may have altered the file on the way. Try again later or from another network; Penteos never installs a file that does not match.");
    }
    return part;
  }

  private fetchTo(url: string, file: string, from: number, total: number, say: (l: string) => void, signal?: AbortSignal, redirects = 0): Promise<void> {
    return new Promise((resolve, reject) => {
      const u = new URL(url);
      if (u.protocol !== "https:" && !(this.options.allowHttp && u.protocol === "http:")) return reject(new ToolboxError("DOWNLOAD_FAILED", `refusing a non-HTTPS download: ${url}`));
      const headers: Record<string, string> = { "user-agent": "Penteos", accept: "application/octet-stream", ...(from > 0 ? { range: `bytes=${from}-` } : {}) };
      const onResponse = (res: IncomingMessage) => {
        const status = res.statusCode ?? 0;
        if ([301, 302, 303, 307, 308].includes(status) && res.headers.location) {
          res.resume();
          if (redirects >= 5) return reject(new Error("too many redirects"));
          return this.fetchTo(new URL(res.headers.location, url).href, file, from, total, say, signal, redirects + 1).then(resolve, reject);
        }
        // 206 continues the partial file; 200 means the server sent it all again.
        if (status !== 200 && status !== 206) {
          res.resume();
          // A range past the end: what we have is (claimed to be) complete; the hash decides.
          if (status === 416) return resolve();
          return reject(new Error(`HTTP ${status}`));
        }
        const fd = openSync(file, status === 206 ? "a" : "w");
        let got = status === 206 ? from : 0;
        let shown = -1;
        res.on("data", (chunk: Buffer) => {
          writeSync(fd, chunk);
          got += chunk.length;
          const pct = Math.floor((got / total) * 100);
          if (pct >= shown + 10) {
            shown = pct - (pct % 10);
            say(`downloading ${Math.min(100, shown)} % (${mb(got)} of ${mb(total)})`);
          }
          if (got > total) res.destroy(new Error("the server sent more than the catalog's size"));
        });
        res.on("end", () => {
          closeSync(fd);
          resolve();
        });
        res.on("error", (e) => {
          try {
            closeSync(fd);
          } catch {
            /* closed */
          }
          reject(e);
        });
        res.on("aborted", () => res.emit("error", new Error("connection cut")));
      };
      const req = this.requestVia(u, headers, onResponse, reject);
      req.setTimeout(this.options.idleTimeoutMs ?? 30_000, () => req.destroy(new Error("no data for too long")));
      signal?.addEventListener("abort", () => req.destroy(new ToolboxError("CANCELLED", "install cancelled")), { once: true });
      req.end();
    });
  }

  /** A GET to the URL, through HTTPS_PROXY when one is set (and the host is not in NO_PROXY). */
  private requestVia(u: URL, headers: Record<string, string>, onResponse: (res: IncomingMessage) => void, onError: (e: Error) => void) {
    const proxy = proxyFor(u);
    if (!proxy || u.protocol === "http:") {
      const req = (u.protocol === "https:" ? httpsRequest : httpRequest)(u, { method: "GET", headers }, onResponse);
      req.on("error", onError);
      return req;
    }
    // HTTPS through an HTTP proxy: CONNECT, then TLS to the real host over that tunnel.
    const port = Number(u.port) || 443;
    const auth = proxy.username ? { "proxy-authorization": `Basic ${Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString("base64")}` } : {};
    const req = httpsRequest(u, {
      method: "GET",
      headers,
      createConnection: (_opts: unknown, cb: (err: Error | null, socket: import("node:net").Socket) => void) => {
        const c = httpRequest({ host: proxy.hostname, port: Number(proxy.port) || 80, method: "CONNECT", path: `${u.hostname}:${port}`, headers: { host: `${u.hostname}:${port}`, ...auth } });
        c.once("connect", (res, socket) => {
          if (res.statusCode !== 200) return cb(new Error(`the proxy answered ${res.statusCode} to CONNECT`), undefined as never);
          cb(null, tlsConnect({ socket, servername: u.hostname }));
        });
        c.once("error", (e) => cb(e, undefined as never));
        c.end();
        return undefined as never;
      },
    } as never, onResponse);
    req.on("error", onError);
    return req;
  }

  // -------------------------------------------------------------------------------------------
  // State

  private state(): State {
    try {
      const s = JSON.parse(readFileSync(this.stateFile, "utf8")) as State;
      return s && typeof s.tools === "object" ? s : { tools: {} };
    } catch {
      return { tools: {} };
    }
  }

  private save(state: State): void {
    const tmp = `${this.stateFile}.${randomBytes(4).toString("hex")}.tmp`;
    writeFileSync(tmp, JSON.stringify(state, null, 2));
    renameSync(tmp, this.stateFile);
  }

  /**
   * After a crash or a cut: staging folders and stray links go; partial downloads stay (they
   * resume); a tool whose files vanished is no longer listed as installed.
   */
  private recover(): void {
    for (const tool of safeList(this.pkgsDir)) for (const d of safeList(join(this.pkgsDir, tool))) if (d.startsWith(".tmp-")) rmSync(join(this.pkgsDir, tool, d), { recursive: true, force: true });
    for (const l of safeList(this.binDir)) if (l.startsWith(".tmp-")) rmSync(join(this.binDir, l), { force: true });
    for (const f of safeList(this.dir)) if (f.startsWith(".probe-") || /^state\.json\..*\.tmp$/.test(f)) rmSync(join(this.dir, f), { force: true });
    const state = this.state();
    let changed = false;
    for (const [name, t] of Object.entries(state.tools)) {
      if (!existsSync(join(this.dir, t.binary))) {
        delete state.tools[name];
        changed = true;
      }
    }
    if (changed) this.save(state);
  }
}

// ---------------------------------------------------------------------------------------------

function proxyFor(u: URL): URL | undefined {
  const raw = process.env.HTTPS_PROXY ?? process.env.https_proxy ?? process.env.ALL_PROXY ?? process.env.all_proxy;
  if (!raw) return undefined;
  const skip = (process.env.NO_PROXY ?? process.env.no_proxy ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const host = u.hostname.toLowerCase();
  if (skip.some((s) => s === "*" || host === s.replace(/^\./, "") || host.endsWith(s.startsWith(".") ? s : `.${s}`))) return undefined;
  try {
    return new URL(/^\w+:\/\//.test(raw) ? raw : `http://${raw}`);
  } catch {
    return undefined;
  }
}

function freeBytes(dir: string): number | undefined {
  try {
    const s = statfsSync(dir);
    return Number(s.bavail) * Number(s.bsize);
  } catch {
    return undefined;
  }
}

function dirSize(path: string): number {
  let total = 0;
  for (const name of safeList(path)) {
    const p = join(path, name);
    try {
      const s = lstatSync(p);
      total += s.isDirectory() ? dirSize(p) : s.isFile() ? s.size : 0;
    } catch {
      /* gone meanwhile */
    }
  }
  return total;
}

function safeList(path: string): string[] {
  try {
    return readdirSync(path);
  } catch {
    return [];
  }
}

function sha256File(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    createReadStream(path)
      .on("data", (c) => h.update(c))
      .on("end", () => resolve(h.digest("hex")))
      .on("error", reject);
  });
}

function runsSync(path: string): boolean {
  try {
    execFileSync(path, [], { timeout: 5000, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(new ToolboxError("CANCELLED", "install cancelled"));
      },
      { once: true },
    );
  });
}

/** Runs uv, its output going to the run line by line; a failure says uv's last words. */
function runUv(uv: string, args: string[], env: NodeJS.ProcessEnv, say: (l: string) => void, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = execFile(uv, args, { env, timeout: 20 * 60_000, maxBuffer: 16 * 1024 * 1024, ...(signal ? { signal } : {}) }, (error, _stdout, stderr) => {
      if (!error) return resolve();
      const last = String(stderr ?? "").trim().split("\n").slice(-4).join(" ");
      const code = /hash/i.test(last) && /mismatch|does not match|expected/i.test(last) ? "HASH_MISMATCH" : "DOWNLOAD_FAILED";
      reject(new ToolboxError(code, `uv ${args[0]} failed: ${last || error.message}`, code === "HASH_MISMATCH" ? "A package did not match its locked hash: nothing was installed." : "Check the connection (or HTTPS_PROXY); uv resumes what it already has."));
    });
    child.stderr?.on("data", (d: Buffer) => {
      for (const line of d.toString().split("\n")) if (line.trim() && !/^\s*$/.test(line)) say(line.trim().slice(0, 200));
    });
  });
}

/** One regular file in a ustar archive (names here are short: tool-version-platform.ext). */
function writeTarEntry(fd: number, name: string, data: Buffer): void {
  const h = Buffer.alloc(512);
  h.write(name.slice(0, 99), 0);
  h.write("0000644\0", 100);
  h.write("0000000\0", 108);
  h.write("0000000\0", 116);
  h.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124);
  h.write(`${Math.floor(Date.now() / 1000).toString(8).padStart(11, "0")}\0`, 136);
  h.write("        ", 148);
  h.write("0", 156);
  h.write("ustar\u000000", 257);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148);
  writeSync(fd, h);
  writeSync(fd, data);
  const pad = (512 - (data.length % 512)) % 512;
  if (pad) writeSync(fd, Buffer.alloc(pad));
}

export function mb(bytes: number): string {
  return bytes >= 1e9 ? `${(bytes / 1e9).toFixed(1)} GB` : `${(bytes / 1e6).toFixed(bytes < 1e7 ? 1 : 0)} MB`;
}

/** Runs a candidate binary with the identity arguments; the text it printed, colors removed. */
export function runForIdentity(binary: string, args: string[]): Promise<string> {
  return new Promise((resolve) => {
    execFile(binary, args, { timeout: 10_000, env: { ...process.env, NO_COLOR: "1" } }, (error, stdout, stderr) => {
      const out = `${stdout ?? ""}\n${stderr ?? ""}`.replace(/\x1b\[[0-9;]*m/g, "");
      resolve(error && !out.trim() ? `__error__ ${error.message}` : out);
    });
  });
}

