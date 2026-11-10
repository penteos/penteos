// Every production dependency that ships inside Penteos, with its license and notice texts, in one
// file next to the bundle (the bundler folds the packages into core.mjs and their LICENSE files
// would be lost; licenses like Apache-2.0 ask for their text and NOTICE to travel with the work).
//
//   node scripts/licenses.mjs <out-file>
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** The license and notice files a package carries (LICENSE, LICENCE, COPYING, NOTICE…). */
function texts(dir) {
  if (!dir || !existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => /^(licen[cs]e|copying|notice)([._-].*)?$/i.test(f))
    .sort()
    .map((f) => ({ file: f, text: readFileSync(join(dir, f), "utf8").trim() }));
}

export function thirdPartyLicenses() {
  const raw = execFileSync("pnpm", ["licenses", "list", "--prod", "--json"], { cwd: root, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  const byLicense = JSON.parse(raw);
  const packages = Object.entries(byLicense)
    .flatMap(([license, list]) => list.map((p) => ({ ...p, license })))
    .filter((p) => !p.name.startsWith("@penteos/"))
    .sort((a, b) => a.name.localeCompare(b.name));
  const parts = [
    "Third-party software shipped with Penteos",
    "=========================================",
    "",
    "Penteos is licensed under the GNU AGPL-3.0. It includes the packages below, each under its own",
    "license. Their license and notice texts follow, as each package distributes them.",
    "",
  ];
  for (const p of packages) {
    const versions = (p.versions ?? [p.version]).filter(Boolean).join(", ");
    parts.push("-".repeat(100), `${p.name} ${versions}`.trim(), `License: ${p.license}`);
    if (p.homepage) parts.push(`Homepage: ${p.homepage}`);
    const found = texts(p.paths?.[0] ?? p.path);
    if (!found.length) parts.push("", `(No license file in the package: ${p.license} applies, as declared in its package.json.)`);
    for (const t of found) parts.push("", `[${t.file}]`, "", t.text);
    parts.push("");
  }
  return { text: parts.join("\n"), count: packages.length };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = resolve(process.argv[2] ?? join(root, "THIRD_PARTY_LICENSES.txt"));
  const { text, count } = thirdPartyLicenses();
  writeFileSync(out, text);
  console.log(`${count} packages → ${out}`);
}
