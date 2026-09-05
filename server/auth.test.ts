import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ROLE_PERMISSIONS, hashPassword, verifyPassword } from "./auth";

describe("Auth", () => {
  it("hashes and verifies passwords", async () => {
    const hash = await hashPassword("TestPassword123!");
    assert.notEqual(hash, "TestPassword123!");
    assert.equal(await verifyPassword("TestPassword123!", hash), true);
    assert.equal(await verifyPassword("wrong", hash), false);
  });

  it("defines role permissions", () => {
    assert.ok(ROLE_PERMISSIONS.admin.includes("*"));
    assert.ok(ROLE_PERMISSIONS.analyst.includes("predict"));
    assert.ok(ROLE_PERMISSIONS.viewer.includes("view_dashboard"));
  });
});

describe("Schema", () => {
  it("exports attack stages", async () => {
    const { attackStageEnum } = await import("@shared/schema");
    assert.ok(attackStageEnum.enumValues.includes("reconnaissance"));
    assert.ok(attackStageEnum.enumValues.includes("data_exfiltration"));
  });
});
