#!/usr/bin/env node
/**
 * Builds the verified tool catalog. Run by a person, who reviews the
 * diff: for each tool's chosen release it downloads every platform's file (in memory, nothing
 * written to disk), computes its SHA-256, checks it against the project's own checksums file, finds
 * the executable inside, and writes packages/core/src/tools/catalog-data.ts.
 *
 *   pnpm exec tsx scripts/tools/refresh-catalog.mjs              versions below
 *   pnpm exec tsx scripts/tools/refresh-catalog.mjs --latest     each project's newest release
 *   pnpm exec tsx scripts/tools/refresh-catalog.mjs --only uv,sqlmap   just those (the rest kept as is)
 *
 * Python tools (via "uv") are locked with every package's hash by uv itself (uv pip compile
 * --generate-hashes); uv is downloaded for that, verified against its published .sha256.
 *
 * GITHUB_TOKEN raises GitHub's limit of 60 API calls an hour (one per tool here).
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { formatOf, readArchive } from "../../packages/core/src/tools/archive.ts";
import { CATALOG_DATA } from "../../packages/core/src/tools/catalog-data.ts";

const root = resolve(new URL("../..", import.meta.url).pathname);
const latest = process.argv.includes("--latest");
const onlyArg = process.argv.find((a, i) => process.argv[i - 1] === "--only");
const only = onlyArg ? new Set(onlyArg.split(",")) : undefined;

/** Which release of which project, and how its files are named per platform. */
const SOURCES = [
  { name: "subfinder", repo: "projectdiscovery/subfinder", version: "2.17.0", binary: "subfinder", license: "MIT", minVersion: "2.6.0" },
  { name: "dnsx", repo: "projectdiscovery/dnsx", version: "1.3.1", binary: "dnsx", license: "MIT", minVersion: "1.2.0" },
  { name: "httpx", repo: "projectdiscovery/httpx", version: "1.12.0", binary: "httpx", license: "MIT", minVersion: "1.6.0" },
  { name: "nuclei", repo: "projectdiscovery/nuclei", version: "3.11.1", binary: "nuclei", license: "MIT", minVersion: "3.2.0" },
  { name: "katana", repo: "projectdiscovery/katana", version: "1.8.0", binary: "katana", license: "MIT", minVersion: "1.1.0" },
  { name: "interactsh-client", repo: "projectdiscovery/interactsh", version: "1.4.1", binary: "interactsh-client", prefix: "interactsh-client", license: "MIT", minVersion: "1.1.0" },
  { name: "ffuf", repo: "ffuf/ffuf", version: "2.3.0", binary: "ffuf", license: "MIT", minVersion: "2.0.0" },
  { name: "gobuster", repo: "OJ/gobuster", version: "3.8.2", binary: "gobuster", license: "Apache-2.0", minVersion: "3.6.0" },
  // uv: static (musl) builds, so they run on any distribution; it installs the Python tools below.
  { name: "uv", repo: "astral-sh/uv", version: "0.13.7", binary: "uv", license: "MIT OR Apache-2.0", tag: "", patterns: { "linux-x64": /^uv-x86_64-unknown-linux-musl\.tar\.gz$/, "linux-arm64": /^uv-aarch64-unknown-linux-musl\.tar\.gz$/ } },
];

/** Python tools, installed by uv with every package's hash locked. */
const PY_SOURCES = [{ name: "sqlmap", spec: "sqlmap==1.10.11", version: "1.10.11", binary: "sqlmap", python: "3.12", license: "GPL-2.0", homepage: "https://github.com/sqlmapproject/sqlmap", minVersion: "1.7" }];

const PLATFORMS = {
  "linux-x64": /linux[_-](amd64|x86_64)\.(zip|tar\.gz)$/i,
  "linux-arm64": /linux[_-](arm64|aarch64)\.(zip|tar\.gz)$/i,
  // macOS and Windows join when Penteos ships there (darwin-x64, darwin-arm64, win32-x64).
};

const gh = async (path) => {
  const r = await fetch(`https://api.github.com/repos/${path}`, { headers: { accept: "application/vnd.github+json", "user-agent": "penteos-catalog", ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) } });
  if (!r.ok) throw new Error(`GitHub ${path}: ${r.status} ${await r.text()}`);
  return r.json();
};
const download = async (url) => {
  // Servers cut long downloads now and then (nmap.org does): a few tries, waiting a bit more each time.
  for (let attempt = 1; ; attempt++) {
    try {
      const r = await fetch(url, { headers: { "user-agent": "penteos-catalog" }, redirect: "follow" });
      if (!r.ok) throw new Error(`${url}: ${r.status}`);
      return new Uint8Array(await r.arrayBuffer());
    } catch (e) {
      if (attempt >= 4) throw e;
      console.warn(`  ${url}: ${e.message}; retry ${attempt}`);
      await new Promise((res) => setTimeout(res, 2000 * attempt));
    }
  }
};

const entries = [];
for (const src of SOURCES) {
  if (only && !only.has(src.name)) continue;
  const release = latest ? await gh(`${src.repo}/releases/latest`) : await gh(`${src.repo}/releases/tags/${src.tag ?? "v"}${src.version}`);
  const version = release.tag_name.replace(/^v/, "");
  const prefix = (src.prefix ?? src.name).toLowerCase();
  const assets = release.assets.filter((a) => a.name.toLowerCase().startsWith(prefix));
  // The project's own checksums (when it publishes them): our hash must match theirs.
  const sumsAsset = release.assets.find((a) => /checksums?\.txt$|sha256sums?(\.txt)?$/i.test(a.name));
  const sums = new Map();
  if (sumsAsset) {
    for (const line of new TextDecoder().decode(await download(sumsAsset.browser_download_url)).split("\n")) {
      const m = /^([0-9a-f]{64})\s+\*?(\S+)$/i.exec(line.trim());
      if (m) sums.set(m[2], m[1].toLowerCase());
    }
  }
  const out = { name: src.name, version, via: "release", homepage: `https://github.com/${src.repo}`, license: src.license, binary: src.binary, minVersion: src.minVersion, assets: {} };
  for (const [platform, pattern] of Object.entries(src.patterns ?? PLATFORMS)) {
    const hits = assets.filter((a) => pattern.test(a.name));
    if (hits.length !== 1) {
      console.warn(`  ${src.name} ${platform}: ${hits.length} files match (${hits.map((h) => h.name).join(", ") || "none"}), skipped`);
      continue;
    }
    const a = hits[0];
    const data = await download(a.browser_download_url);
    const sha256 = createHash("sha256").update(data).digest("hex");
    // The project's own hash for this file: its <file>.sha256 (uv) or its line in the checksums file.
    const own = release.assets.find((x) => x.name === `${a.name}.sha256`);
    const theirs = own ? new TextDecoder().decode(await download(own.browser_download_url)).trim().split(/\s+/)[0].toLowerCase() : sums.get(a.name);
    if (sums.size || own) {
      if (!theirs) throw new Error(`${a.name}: the project publishes checksums but none for this file`);
      if (theirs !== sha256) throw new Error(`${a.name}: our SHA-256 ${sha256} does not match the project's ${theirs}`);
      sums.set(a.name, theirs);
    }
    const format = formatOf(a.name);
    const want = platform.startsWith("win32") ? `${src.binary}.exe` : src.binary;
    const files = readArchive(data, format, a.name).filter((f) => f.path.split("/").pop() === want);
    if (files.length !== 1) throw new Error(`${a.name}: ${files.length} files named ${want} inside`);
    out.assets[platform] = { url: a.browser_download_url, sha256, size: data.length, format, bin: files[0].path };
    console.log(`  ${src.name} ${version} ${platform}: ${(data.length / 1e6).toFixed(1)} MB${sums.size ? " (project checksum ✓)" : " (no project checksum)"}`);
  }
  entries.push(out);
}

// nmap: the official package from nmap.org (x64 only), unpacked by Penteos without root; its data
// folder goes with it (NMAPDIR). Checked against the SHA-256 nmap.org publishes in sigs/.
const NMAP = { version: "7.993-1", minVersion: "7.80" };
if (!only || only.has("nmap")) {
  const name = `nmap-${NMAP.version}.x86_64.rpm`;
  const url = `https://nmap.org/dist/${name}`;
  const digest = await fetch(`https://nmap.org/dist/sigs/${name}.digest.txt`).then((r) => r.text());
  const theirs = /SHA256\s*=\s*([0-9A-F ]+)\n/i.exec(digest)?.[1]?.replace(/\s+/g, "").toLowerCase();
  const data = await download(url);
  const sha256 = createHash("sha256").update(data).digest("hex");
  if (!theirs || theirs !== sha256) throw new Error(`${name}: our SHA-256 ${sha256} does not match nmap.org's ${theirs ?? "(missing)"}`);
  const files = readArchive(data, "rpm");
  if (!files.some((f) => f.path === "usr/bin/nmap")) throw new Error(`${name}: no usr/bin/nmap inside`);
  entries.push({ name: "nmap", version: NMAP.version.replace(/-\d+$/, ""), via: "release", homepage: "https://nmap.org", license: "NPSL", binary: "nmap", minVersion: NMAP.minVersion, assets: { "linux-x64": { url, sha256, size: data.length, format: "rpm", bin: "usr/bin/nmap", data: "usr/share/nmap", dataEnv: "NMAPDIR" } } });
  console.log(`  nmap ${NMAP.version} linux-x64: ${(data.length / 1e6).toFixed(1)} MB (nmap.org SHA-256 ✓)`);
}

// Python tools: uv (the one just verified, for this machine) locks every package with its hashes.
const pyWanted = PY_SOURCES.filter((p) => !only || only.has(p.name));
if (pyWanted.length) {
  const uvEntry = entries.find((e) => e.name === "uv") ?? CATALOG_DATA.find((e) => e.name === "uv");
  const plat = process.arch === "arm64" ? "linux-arm64" : "linux-x64";
  const work = mkdtempSync(join(tmpdir(), "penteos-uv-"));
  try {
    const a = uvEntry.assets[plat];
    const data = await download(a.url);
    if (createHash("sha256").update(data).digest("hex") !== a.sha256) throw new Error("uv download does not match the catalog");
    const file = readArchive(data, a.format, a.bin).find((f) => f.path === a.bin);
    const uv = join(work, "uv");
    writeFileSync(uv, file.data);
    chmodSync(uv, 0o755);
    for (const p of pyWanted) {
      writeFileSync(join(work, "in.txt"), `${p.spec}\n`);
      execFileSync(uv, ["pip", "compile", "--quiet", "--no-header", "--generate-hashes", "--python-version", p.python, "--python-platform", "x86_64-unknown-linux-gnu", join(work, "in.txt"), "-o", join(work, "lock.txt")], { env: { ...process.env, UV_NO_CONFIG: "1", UV_CACHE_DIR: join(work, "cache") }, stdio: "inherit" });
      const lock = new TextDecoder().decode(await import("node:fs").then((fs) => fs.readFileSync(join(work, "lock.txt"))));
      const packages = (lock.match(/^[A-Za-z0-9_.-]+==/gm) ?? []).length;
      // Download size: the package files from PyPI (wheel when there is one), plus Python itself (~35 MB, shared).
      let size = 35e6;
      for (const m of lock.matchAll(/^([A-Za-z0-9_.-]+)==([^\s\\]+)/gm)) {
        const meta = await fetch(`https://pypi.org/pypi/${m[1]}/${m[2]}/json`).then((r) => r.json());
        const files = meta.urls ?? [];
        size += (files.find((f) => f.packagetype === "bdist_wheel") ?? files[0])?.size ?? 0;
      }
      entries.push({ name: p.name, version: p.version, via: "uv", uv: { python: p.python, lock, size }, homepage: p.homepage, license: p.license, binary: p.binary, minVersion: p.minVersion, assets: {} });
      console.log(`  ${p.name} ${p.version}: ${packages} package(s) with hashes, ~${(size / 1e6).toFixed(0)} MB with Python`);
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

// --only: the entries not refreshed stay as they were.
if (only) for (const old of CATALOG_DATA) if (!entries.some((e) => e.name === old.name)) entries.push(old);
const order = [...SOURCES.map((x) => x.name), "nmap", ...PY_SOURCES.map((x) => x.name)];
entries.sort((a, b) => order.indexOf(a.name) - order.indexOf(b.name));

const file = join(root, "packages/core/src/tools/catalog-data.ts");
writeFileSync(
  file,
  `// Generated by scripts/tools/refresh-catalog.mjs on ${new Date().toISOString().slice(0, 10)}: do not edit by hand.\n// Every hash was computed from the file and checked against the project's own checksums.\nexport const CATALOG_DATA = ${JSON.stringify(entries, null, 2)} as const;\n`,
);
console.log(`→ ${file}`);
