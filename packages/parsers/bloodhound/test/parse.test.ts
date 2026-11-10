import { IngestBatch } from "@penteos/schema";
import { strToU8, zipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { isBloodHound, parseBloodHound } from "../src/index.js";

const D = "S-1-5-21-1111-2222-3333";
const users = {
  meta: { type: "users", count: 2, version: 6 },
  data: [
    { ObjectIdentifier: `${D}-1104`, Properties: { name: "JDOE@CORP.LOCAL", domain: "CORP.LOCAL", samaccountname: "jdoe", enabled: true } },
    { ObjectIdentifier: `${D}-500`, Properties: { name: "ADMINISTRATOR@CORP.LOCAL", domain: "CORP.LOCAL", samaccountname: "Administrator", enabled: true, admincount: true } },
  ],
};
const groups = {
  meta: { type: "groups", count: 2, version: 6 },
  data: [
    { ObjectIdentifier: `${D}-512`, Properties: { name: "DOMAIN ADMINS@CORP.LOCAL", domain: "CORP.LOCAL", admincount: true }, Members: [{ ObjectIdentifier: `${D}-500`, ObjectType: "User" }] },
    { ObjectIdentifier: `${D}-1200`, Properties: { name: "HELPDESK@CORP.LOCAL", domain: "CORP.LOCAL" }, Members: [{ ObjectIdentifier: `${D}-1104`, ObjectType: "User" }] },
  ],
};
const computers = {
  meta: { type: "computers", count: 1, version: 6 },
  data: [
    {
      ObjectIdentifier: `${D}-1105`,
      Properties: { name: "WS01.CORP.LOCAL", domain: "CORP.LOCAL", enabled: true },
      Sessions: { Results: [{ UserSID: `${D}-500`, ComputerSID: `${D}-1105` }] },
      LocalAdmins: { Results: [{ ObjectIdentifier: `${D}-1200`, ObjectType: "Group" }] },
    },
  ],
};

// SharpHound writes JSON with a UTF-8 BOM, inside a zip.
const zip = zipSync({
  "20261013_users.json": strToU8(`﻿${JSON.stringify(users)}`),
  "20261013_groups.json": strToU8(JSON.stringify(groups)),
  "20261013_computers.json": strToU8(JSON.stringify(computers)),
});

describe("parseBloodHound", () => {
  const batch = parseBloodHound([{ name: "collection.zip", content: zip }], { rawIds: [] });

  it("recognizes SharpHound collections", () => {
    expect(isBloodHound([{ name: "collection.zip", content: zip }])).toBe(true);
    expect(isBloodHound([{ name: "x.json", content: strToU8('{"hello":1}') }])).toBe(false);
  });

  it("produces a valid batch of principals and relations", () => {
    expect(IngestBatch.safeParse(batch).success).toBe(true);
    expect(batch.items).toContainEqual(
      expect.objectContaining({ op: "upsert", kind: "principal", key: { realm: "CORP.LOCAL", name: "domain admins" }, attributes: expect.objectContaining({ principalType: "group", privileged: true }) }),
    );
    expect(batch.items).toContainEqual(expect.objectContaining({ op: "upsert", key: { realm: "CORP.LOCAL", name: "ws01" }, attributes: expect.objectContaining({ principalType: "computer" }) }));
  });

  it("keeps memberships, sessions and local admin rights", () => {
    const rel = (type: string, from: string, to: string) =>
      expect(batch.items).toContainEqual({ op: "relate", type, from: { kind: "principal", key: { realm: "CORP.LOCAL", name: from } }, to: { kind: "principal", key: { realm: "CORP.LOCAL", name: to } } });
    rel("member_of", "jdoe", "helpdesk");
    rel("member_of", "administrator", "domain admins");
    rel("has_session", "administrator", "ws01");
    rel("admin_to", "helpdesk", "ws01");
  });
});
