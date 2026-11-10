import type { Actor } from "@penteos/schema";
import { beforeEach, expect, it } from "vitest";
import { z } from "zod";
import { agentInputJsonSchema, defineOperation, executeOperation, getOperation, type OperationContext, OperationError, resetRepeatGuard } from "../src/index.js";

/** The agent loop's safety nets: repetition guard, argument repair and the intent field. */

const agent: Actor = { type: "agent", id: "01JA000000000000000000LOOP" };
const human: Actor = { type: "human", id: "01JA000000000000000000HUMN" };
let calls = 0;

defineOperation({
  name: "test.act",
  title: "Act",
  description: "test",
  kind: "write",
  actors: ["agent", "human"],
  input: z.object({ target: z.string(), ports: z.array(z.number()).default([]), wait: z.number().optional(), deep: z.boolean().optional(), maxCount: z.number().optional() }),
  handler: (input) => ({ status: "done", n: ++calls, input }),
});
defineOperation({
  name: "test.fail",
  title: "Fail",
  description: "test",
  kind: "target",
  actors: ["agent"],
  input: z.object({ x: z.string() }),
  handler: () => {
    calls++;
    throw new OperationError("HOST_BUSY", "busy");
  },
});
defineOperation({
  name: "test.read",
  title: "Read",
  description: "test",
  kind: "read",
  actors: ["agent"],
  input: z.object({}),
  handler: () => ({ n: ++calls }),
});

const ctx = (actor: Actor = agent): OperationContext =>
  ({ caller: { actor, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } }, defaultEngagementId: "E1" }) as unknown as OperationContext;

beforeEach(() => {
  calls = 0;
  resetRepeatGuard(agent.id);
});

it("echoes the third identical action instead of running it, and refuses the sixth", async () => {
  const a = { target: "10.0.0.1" };
  await executeOperation("test.act", a, ctx());
  await executeOperation("test.act", a, ctx());
  const third = (await executeOperation("test.act", a, ctx())) as { n: number; repeatedCall?: string };
  expect(calls).toBe(2);
  expect(third.n).toBe(2);
  expect(third.repeatedCall).toMatch(/change approach/);
  await executeOperation("test.act", a, ctx());
  await executeOperation("test.act", a, ctx());
  await expect(executeOperation("test.act", a, ctx())).rejects.toMatchObject({ code: "REPEATED" });
  expect(calls).toBe(2);
});

it("catches an A-B-A-B loop and ignores the intent and key order", async () => {
  for (let i = 0; i < 3; i++) {
    await executeOperation("test.act", { target: "a", ports: [80], intent: `try ${i}` }, ctx());
    await executeOperation("test.act", { ports: [80], target: "b" }, ctx());
  }
  expect(calls).toBe(4);
});

it("echoes a repeated failure as the same error", async () => {
  for (let i = 0; i < 2; i++) await expect(executeOperation("test.fail", { x: "1" }, ctx())).rejects.toMatchObject({ code: "HOST_BUSY" });
  await expect(executeOperation("test.fail", { x: "1" }, ctx())).rejects.toThrow(/did not run it again/);
  expect(calls).toBe(2);
});

it("never holds back reads, people, or an agent a person just spoke to", async () => {
  for (let i = 0; i < 4; i++) await executeOperation("test.read", {}, ctx());
  expect(calls).toBe(4);
  calls = 0;
  for (let i = 0; i < 4; i++) await executeOperation("test.act", { target: "h" }, ctx(human));
  expect(calls).toBe(4);
  calls = 0;
  await executeOperation("test.act", { target: "z" }, ctx());
  await executeOperation("test.act", { target: "z" }, ctx());
  resetRepeatGuard(agent.id);
  await executeOperation("test.act", { target: "z" }, ctx());
  expect(calls).toBe(3);
});

it("repairs near-miss arguments from an agent", async () => {
  const r = (await executeOperation("test.act", { target: "t", ports: "[80, 443]", wait: "30", deep: "true", max_count: 5 }, ctx())) as { input: Record<string, unknown> };
  expect(r.input).toEqual({ target: "t", ports: [80, 443], wait: 30, deep: true, maxCount: 5 });
  const single = (await executeOperation("test.act", { target: "t2", ports: 22 }, ctx())) as { input: { ports: number[] } };
  expect(single.input.ports).toEqual([22]);
});

it("explains what a field expects when the input cannot be repaired", async () => {
  await expect(executeOperation("test.act", { ports: ["x"] }, ctx())).rejects.toThrow(/target: .*expects \{"type":"string"\}/);
});

it("strips the intent before the operation sees it, and offers it in the agent's schema", async () => {
  const r = (await executeOperation("test.act", { target: "t3", intent: "see what answers" }, ctx())) as { input: Record<string, unknown> };
  expect(r.input).not.toHaveProperty("intent");
  const schema = agentInputJsonSchema(getOperation("test.act")!) as { properties: Record<string, unknown> };
  expect(schema.properties).toHaveProperty("intent");
});
