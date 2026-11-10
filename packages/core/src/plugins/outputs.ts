import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { extname, join, relative, resolve, sep } from "node:path";
import { ulid } from "@penteos/schema";

/**
 * Files a plugin makes for the operator: a report, a CSV, an
 * image, a zip. They live in the project's folder, under `plugins/<id>/files/`, so they are part of
 * the project: backed up with it, exported with it, deleted with it. Any plugin writes them through
 * the core (the `file` step); a free plugin can also write there itself, it gets the path per call.
 */

export const OUTPUT_LIMITS = {
  /** One file written through the core (a free plugin writing directly is not limited). */
  fileBytes: 100 * 1024 * 1024,
  /** What one plugin keeps in one project, counted before writing through the core. */
  totalBytes: 2 * 1024 * 1024 * 1024,
  /** Entries listed (the rest are counted, not listed). */
  listed: 500,
  /** A file read back for the interface (download, preview). */
  readBytes: 200 * 1024 * 1024,
} as const;

export interface OutputFile {
  /** Path inside the plugin's output folder, with "/" ("informes/acme.docx"). */
  name: string;
  size: number;
  modifiedAt: string;
  type: string;
}

export class OutputError extends Error {}

/** The folder where a plugin's files for one project go. */
export function outputDir(projectDir: string, pluginId: string): string {
  return join(projectDir, "plugins", pluginId, "files");
}

/** A name a plugin gave, checked: relative, no "..", no hidden or odd segments, a sane length. */
export function outputName(raw: string): string {
  const name = String(raw).trim().replace(/\\/g, "/").replace(/\/+/g, "/").replace(/^\.\//, "");
  if (!name || name.length > 200) throw new OutputError("the file name is empty or longer than 200 characters");
  if (name.startsWith("/") || /^[A-Za-z]:/.test(name)) throw new OutputError(`"${name}" must be a name inside the plugin's folder, not an absolute path`);
  const parts = name.split("/");
  if (parts.length > 6) throw new OutputError(`"${name}" has too many folders`);
  for (const part of parts) {
    if (!part || part === "." || part === ".." || part.startsWith(".")) throw new OutputError(`"${name}": folders and files cannot be empty or start with a dot`);
    // Control characters and the few that break on Windows file systems.
    if (/[\u0000-\u001f<>:"|?*]/.test(part)) throw new OutputError(`"${name}" has characters a file name cannot have`);
  }
  return parts.join("/");
}

/** The absolute path of `name` inside `dir`, refusing anything that lands outside (links included). */
function inside(dir: string, name: string, mustExist: boolean): string {
  const path = resolve(dir, outputName(name));
  if (!path.startsWith(resolve(dir) + sep)) throw new OutputError(`"${name}" is outside the plugin's folder`);
  if (mustExist) {
    if (!existsSync(path)) throw new OutputError(`there is no file "${name}"`);
    const real = realpathSync(path);
    if (!real.startsWith(realpathSync(dir) + sep)) throw new OutputError(`"${name}" points outside the plugin's folder`);
  }
  return path;
}

const TYPES: Record<string, string> = {
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  ".odt": "application/vnd.oasis.opendocument.text",
  ".ods": "application/vnd.oasis.opendocument.spreadsheet",
  ".pdf": "application/pdf",
  ".csv": "text/csv",
  ".tsv": "text/tab-separated-values",
  ".txt": "text/plain",
  ".log": "text/plain",
  ".md": "text/markdown",
  ".html": "text/html",
  ".htm": "text/html",
  ".json": "application/json",
  ".xml": "application/xml",
  ".yaml": "application/yaml",
  ".yml": "application/yaml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
  ".zip": "application/zip",
  ".gz": "application/gzip",
  ".pcap": "application/vnd.tcpdump.pcap",
};

export function outputType(name: string): string {
  return TYPES[extname(name).toLowerCase()] ?? "application/octet-stream";
}

/** Every file in the folder (newest first), at most `limit`; links are skipped (never followed). */
export function listOutputs(dir: string, limit: number = OUTPUT_LIMITS.listed): { files: OutputFile[]; total: number; bytes: number } {
  const files: OutputFile[] = [];
  let total = 0;
  let bytes = 0;
  if (!existsSync(dir)) return { files, total, bytes };
  const walk = (d: string, depth: number) => {
    if (depth > 6) return;
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      if (entry.name.startsWith(".")) continue;
      const path = join(d, entry.name);
      if (entry.isDirectory()) walk(path, depth + 1);
      else if (entry.isFile()) {
        const st = statSync(path);
        total++;
        bytes += st.size;
        files.push({ name: relative(dir, path).split(sep).join("/"), size: st.size, modifiedAt: st.mtime.toISOString(), type: outputType(entry.name) });
      }
    }
  };
  walk(dir, 0);
  files.sort((a, b) => b.modifiedAt.localeCompare(a.modifiedAt) || a.name.localeCompare(b.name));
  return { files: files.slice(0, limit), total, bytes };
}

/** Writes a file atomically (a half-written report never shows up). Returns what was written. */
export function writeOutput(dir: string, name: string, bytes: Uint8Array): OutputFile {
  if (bytes.byteLength > OUTPUT_LIMITS.fileBytes) throw new OutputError(`"${name}" is larger than ${OUTPUT_LIMITS.fileBytes / 1048576} MB`);
  const clean = outputName(name);
  const path = inside(dir, clean, false);
  const used = listOutputs(dir).bytes - (existsSync(path) ? statSync(path).size : 0);
  if (used + bytes.byteLength > OUTPUT_LIMITS.totalBytes) throw new OutputError(`the plugin's files in this project would pass ${OUTPUT_LIMITS.totalBytes / 1073741824} GB: delete some first`);
  mkdirSync(resolve(path, ".."), { recursive: true });
  // A link planted where the file goes would send the write elsewhere: replace it, never follow it.
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) rmSync(path);
  const parent = realpathSync(resolve(path, ".."));
  if (!(parent + sep).startsWith(realpathSync(dir) + sep)) throw new OutputError(`"${name}" is outside the plugin's folder`);
  const tmp = join(parent, `.${ulid()}.tmp`);
  writeFileSync(tmp, bytes);
  renameSync(tmp, path);
  const st = statSync(path);
  return { name: clean, size: st.size, modifiedAt: st.mtime.toISOString(), type: outputType(clean) };
}

export function readOutput(dir: string, name: string): { bytes: Buffer; file: OutputFile } {
  const path = inside(dir, name, true);
  const st = statSync(path);
  if (!st.isFile()) throw new OutputError(`"${name}" is not a file`);
  if (st.size > OUTPUT_LIMITS.readBytes) throw new OutputError(`"${name}" is larger than ${OUTPUT_LIMITS.readBytes / 1048576} MB: open its folder instead`);
  return { bytes: readFileSync(path), file: { name: outputName(name), size: st.size, modifiedAt: st.mtime.toISOString(), type: outputType(name) } };
}

/** The absolute path of an existing file (to open it with its program or show it in its folder). */
export function outputPath(dir: string, name: string): { path: string; file: OutputFile } {
  const path = inside(dir, name, true);
  const st = statSync(path);
  if (!st.isFile()) throw new OutputError(`"${name}" is not a file`);
  return { path, file: { name: outputName(name), size: st.size, modifiedAt: st.mtime.toISOString(), type: outputType(name) } };
}

export function deleteOutput(dir: string, name: string): void {
  const path = inside(dir, name, false);
  if (!existsSync(path) && !lstatSync(path, { throwIfNoEntry: false })) throw new OutputError(`there is no file "${name}"`);
  rmSync(path, { force: true });
  // Empty folders left behind go too, up to the plugin's folder.
  let d = resolve(path, "..");
  while (d.startsWith(resolve(dir) + sep)) {
    if (readdirSync(d).length > 0) break;
    rmSync(d, { recursive: true });
    d = resolve(d, "..");
  }
}

/** What changed in the folder between two listings: new or rewritten files. */
export function changedOutputs(before: OutputFile[], after: OutputFile[]): OutputFile[] {
  const was = new Map(before.map((f) => [f.name, `${f.size}:${f.modifiedAt}`]));
  return after.filter((f) => was.get(f.name) !== `${f.size}:${f.modifiedAt}`);
}
