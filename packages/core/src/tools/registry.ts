import { execFile } from "node:child_process";
import { accessSync, constants, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, join } from "node:path";
import type { RiskLevel } from "@penteos/schema";
import { BUILTIN_MANIFESTS } from "./builtin-manifests.js";
import { type ToolManifest, validateManifest } from "./manifest.js";
import { versionAtLeast } from "./catalog.js";
import { mb, type Toolbox } from "./toolbox.js";

export interface ToolStatus {
  name: string;
  description: string;
  risk: RiskLevel;
  source: "builtin" | "custom";
  installed: boolean;
  binary?: string;
  version?: string;
  /** A binary with the expected name exists but is something else (e.g. Python's httpx). */
  mismatch?: string;
  /** Its output is mapped into the graph automatically. */
  integrated: boolean;
  install?: { method: "go"; command: string } | { method: "manual"; command: string } | { method: "catalog"; command: string; version: string; size: number };
  /** Installed by Penteos from the verified catalog (in its tool box), not found on the system. */
  managed?: boolean;
  /** What the verified catalog offers for this machine (installable without root). */
  catalog?: { version: string; size: number; license: string; homepage: string };
  /** Found on the system but older than the catalog's minimum: it works, the catalog's is better. */
  outdated?: boolean;
}

function expand(path: string): string {
  return path.startsWith("~/") ? join(homedir(), path.slice(2)) : path;
}

function findExecutable(binary: string): string | undefined {
  const candidates = binary.includes("/") ? [expand(binary)] : (process.env.PATH ?? "").split(delimiter).map((dir) => join(dir, binary));
  for (const candidate of candidates) {
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      /* next */
    }
  }
  return undefined;
}

function run(binary: string, args: string[]): Promise<string> {
  return new Promise((resolve) => {
    execFile(binary, args, { timeout: 5000, env: { ...process.env, NO_COLOR: "1" } }, (_error, stdout, stderr) => resolve(`${stdout ?? ""}\n${stderr ?? ""}`));
  });
}

export type PackageManager = "apt" | "pacman" | "dnf" | "zypper" | "brew";

/** The system package manager, in order of preference when several are present. */
export function detectPackageManager(): PackageManager | undefined {
  const candidates: Array<[PackageManager, string]> = [["pacman", "pacman"], ["apt", "apt-get"], ["dnf", "dnf"], ["zypper", "zypper"], ["brew", "brew"]];
  return candidates.find(([, bin]) => findExecutable(bin))?.[0];
}

const SYSTEM_INSTALL: Record<PackageManager, (pkg: string) => string> = {
  apt: (p) => `sudo apt install ${p}`,
  pacman: (p) => `sudo pacman -S --needed ${p}`,
  dnf: (p) => `sudo dnf install ${p}`,
  zypper: (p) => `sudo zypper install ${p}`,
  brew: (p) => `brew install ${p}`,
};

/** The command that installs a tool on this machine, or undefined if there is no recipe for it. */
export function installCommand(manifest: ToolManifest, packageManager = detectPackageManager()): string | undefined {
  const install = manifest.install;
  if (!install) return undefined;
  if (install.method === "go") return `go install ${install.package}`;
  if (install.method === "manual") return install.command;
  const pkg = packageManager ? install.packages[packageManager] : undefined;
  return pkg && packageManager ? SYSTEM_INSTALL[packageManager](pkg) : undefined;
}

/**
 * All the tools Penteos knows: built-in manifests plus the ones added at runtime (approved
 * agent proposals or the operator's own), stored as JSON in the data directory.
 */
export class ToolRegistry {
  private readonly manifests = new Map<string, { manifest: ToolManifest; source: "builtin" | "custom" }>();
  private cache: { at: number; status: Map<string, ToolStatus> } | undefined;

  constructor(
    private readonly customDir?: string,
    /** Penteos's own tool box: looked at first, installs from the catalog. */
    readonly toolbox?: Toolbox,
  ) {
    for (const raw of BUILTIN_MANIFESTS) {
      const m = validateManifest(raw);
      this.manifests.set(m.name, { manifest: m, source: "builtin" });
    }
    if (customDir) {
      mkdirSync(customDir, { recursive: true });
      for (const file of readdirSync(customDir).filter((f) => f.endsWith(".json"))) {
        try {
          const m = validateManifest(JSON.parse(readFileSync(join(customDir, file), "utf8")));
          this.manifests.set(m.name, { manifest: m, source: "custom" });
        } catch {
          /* an invalid file is ignored, never fatal */
        }
      }
    }
  }

  all(): ToolManifest[] {
    return [...this.manifests.values()].map((e) => e.manifest);
  }

  get(name: string): ToolManifest | undefined {
    return this.manifests.get(name)?.manifest;
  }

  /** The manifest for a command name: its own name or any of its binaries' names. */
  forBinary(command: string): ToolManifest | undefined {
    const base = command.split("/").pop()!;
    return this.get(base) ?? this.all().find((m) => m.binaries.some((b) => b.split("/").pop() === base));
  }

  save(input: unknown): ToolManifest {
    if (!this.customDir) throw new Error("this registry cannot store manifests");
    const manifest = validateManifest(input);
    writeFileSync(join(this.customDir, `${manifest.name}.json`), JSON.stringify(manifest, null, 2), { mode: 0o600 });
    this.manifests.set(manifest.name, { manifest, source: "custom" });
    this.invalidate();
    return manifest;
  }

  invalidate(): void {
    this.cache = undefined;
  }

  private async detect(manifest: ToolManifest, source: "builtin" | "custom"): Promise<ToolStatus> {
    const fromCatalog = this.toolbox?.asset(manifest.name) && this.toolbox.entry(manifest.name);
    const asset = this.toolbox?.asset(manifest.name);
    const command = installCommand(manifest);
    // The verified catalog first: no root, no compiler, the same on every distribution.
    const install: ToolStatus["install"] =
      fromCatalog && asset
        ? { method: "catalog", command: `Penteos: ${manifest.name} ${fromCatalog.version} (${mb(asset.size)}, verified)`, version: fromCatalog.version, size: asset.size }
        : command
          ? { method: manifest.install?.method === "go" ? "go" : "manual", command }
          : undefined;
    const base: ToolStatus = {
      name: manifest.name,
      description: manifest.description,
      risk: manifest.risk,
      source,
      installed: false,
      integrated: manifest.name === "nmap" || Boolean(manifest.output),
      ...(install ? { install } : {}),
      ...(fromCatalog && asset ? { catalog: { version: fromCatalog.version, size: asset.size, license: fromCatalog.license, homepage: fromCatalog.homepage } } : {}),
    };
    let mismatch: string | undefined;
    const managed = this.toolbox?.binaryPath(manifest.name);
    for (const candidate of [...(managed ? [managed] : []), ...manifest.binaries]) {
      const path = findExecutable(candidate);
      if (!path) continue;
      const own = path === managed ? { managed: true } : {};
      if (!manifest.identity) return { ...base, ...own, installed: true, binary: path };
      // Tools color their banners and change the case between versions ("Current Version" in older
      // ProjectDiscovery releases, "Current version" in katana 1.8): compare plain, case-insensitive text.
      const out = (await run(path, manifest.identity.args)).replace(/\x1b\[[0-9;]*m/g, "");
      const m = new RegExp(manifest.identity.pattern, "mi").exec(out);
      if (m) {
        // A tool from the box: the version Penteos installed and verified, not one parsed from a banner.
        const version = (own.managed ? this.toolbox?.get(manifest.name)?.version : undefined) ?? /v?(\d+\.\d+[\w.-]*)/.exec(m[0])?.[1] ?? m[0];
        const outdated = !own.managed && fromCatalog?.minVersion && !versionAtLeast(version, fromCatalog.minVersion) ? { outdated: true } : {};
        return { ...base, ...own, ...outdated, installed: true, binary: path, version };
      }
      mismatch = `${path} exists but is not ${manifest.description}`;
    }
    return { ...base, ...(mismatch ? { mismatch } : {}) };
  }

  async status(force = false): Promise<ToolStatus[]> {
    if (force || !this.cache || Date.now() - this.cache.at > 60_000) {
      const list = await Promise.all([...this.manifests.values()].map((e) => this.detect(e.manifest, e.source)));
      this.cache = { at: Date.now(), status: new Map(list.map((s) => [s.name, s])) };
    }
    return [...this.cache.status.values()];
  }

  /** The verified binary to execute for a manifest, or undefined if it is not installed. */
  async binaryFor(manifest: ToolManifest): Promise<ToolStatus> {
    const cached = this.cache?.status.get(manifest.name);
    if (cached && Date.now() - (this.cache?.at ?? 0) < 60_000) return cached;
    const status = await this.detect(manifest, this.manifests.get(manifest.name)?.source ?? "custom");
    if (this.cache) this.cache.status.set(manifest.name, status);
    return status;
  }
}
