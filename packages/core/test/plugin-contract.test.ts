import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PluginManifest, SUPPORTED_PLUGIN_API_VERSIONS } from "@penteos/schema";
import { describe, expect, it } from "vitest";
import { testDraft } from "../src/index.js";

/**
 * The contract suite: sample plugins for every
 * apiVersion the core still supports, together using every extension point, each run in the
 * sandbox with what it must do. A change to the core that breaks one of them does not ship.
 */

const root = join(dirname(fileURLToPath(import.meta.url)), "contract");

interface Contract {
  operation: string;
  input?: Record<string, unknown>;
  settings?: Record<string, unknown>;
  responses?: never[];
  fixtures?: never;
  expect: { result?: Record<string, unknown>; steps?: number; entities?: number; findings?: number; annotations?: number };
}

describe("plugin contract", () => {
  it("every supported apiVersion has sample plugins", () => {
    for (const v of SUPPORTED_PLUGIN_API_VERSIONS) expect(existsSync(join(root, `v${v}`)), `test/contract/v${v}`).toBe(true);
  });

  for (const version of readdirSync(root).filter((d) => /^v\d+$/.test(d))) {
    for (const name of readdirSync(join(root, version))) {
      const dir = join(root, version, name);
      it(`${version}/${name} validates and does what it must`, async () => {
        const raw = JSON.parse(readFileSync(join(dir, "plugin.json"), "utf8"));
        const parsed = PluginManifest.safeParse(raw);
        expect(parsed.success ? "" : parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join(" | ")).toBe("");
        expect(`v${raw.apiVersion}`).toBe(version);
        const contract = JSON.parse(readFileSync(join(dir, "contract.json"), "utf8")) as Contract;
        const report = await testDraft(raw, { ...contract, expect: undefined }, { sourceDir: dir });
        expect(report.error ?? "").toBe("");
        expect(report.ok).toBe(true);
        if (contract.expect.result) expect(report.result).toMatchObject(contract.expect.result);
        if (contract.expect.steps !== undefined) expect(report.steps).toHaveLength(contract.expect.steps);
        if (contract.expect.entities !== undefined) expect(report.wrote.entities).toHaveLength(contract.expect.entities);
        if (contract.expect.findings !== undefined) expect(report.wrote.findings).toHaveLength(contract.expect.findings);
        if (contract.expect.annotations !== undefined) expect(report.wrote.annotations).toHaveLength(contract.expect.annotations);
        expect(report.requests.every((r) => r.matched)).toBe(true);
      }, 30_000);
    }
  }
});
