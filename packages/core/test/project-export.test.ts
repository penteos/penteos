import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, expect, it } from "vitest";
import { Workspace } from "../src/index.js";

/** A .penteos file round-trips the project into a different workspace, with the vault secrets stripped. */

const human: Actor = { type: "human", id: "01JA000000000000000000HUMN" };
let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "penteos-export-test-"));
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

it("exports a project to .penteos and imports it into another workspace without secret values", async () => {
  const wsA = new Workspace(join(root, "a"));
  const eng = wsA.create({ clientName: "ACME", name: "Web audit", mode: "web" }, human);
  eng.saveSecret({ name: "api_token", kind: "token", value: "s3cr3t-value" }, human);
  expect(eng.secretValue("api_token")).toBe("s3cr3t-value");

  const file = join(root, "acme.penteos");
  const { secretsStripped } = await wsA.exportEngagement(eng.info.id, file);
  expect(secretsStripped).toBe(1);
  wsA.close();

  // A different workspace means a different vault key: the project must still open.
  const wsB = new Workspace(join(root, "b"));
  const summary = wsB.importEngagement(file, human);
  expect(summary.clientName).toBe("ACME");
  expect(summary.name).toBe("Web audit");
  expect(summary.mode).toBe("web");
  expect(wsB.list().map((e) => e.id)).toContain(summary.id);

  const imported = wsB.get(summary.id);
  expect(imported.info.id).toBe(summary.id); // id realigned with the folder
  // The secret's name survives so the operator knows what to re-enter, but its value is gone.
  expect(imported.secrets().map((s) => s.name)).toEqual(["api_token"]);
  expect(imported.secretValue("api_token")).toBe("");
  wsB.close();
});
