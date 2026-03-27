import { describe, expect, test } from "bun:test";
import { debugCan, debugRole } from "../src/debug";
import { defineRoles } from "../src/define";

const config = defineRoles({
	roles: {
		owner: { permissions: ["*"] },
		admin: {
			permissions: ["workspace:update", "members:invite", "brands:*"],
			deny: ["brands:delete"],
		},
		viewer: { permissions: ["workspace:read", "brands:read"] },
	},
	hierarchy: ["owner", "admin", "viewer"],
	superAdmin: "owner",
});

describe("debugCan", () => {
	test("explains superAdmin bypass", () => {
		const result = debugCan(config, "owner", "anything:here");
		expect(result.allowed).toBe(true);
		expect(result.traces[0].reason).toContain("superAdmin");
		expect(result.effectivePermissions).toEqual(["*"]);
	});

	test("explains direct permission match", () => {
		const result = debugCan(config, "viewer", "workspace:read");
		expect(result.allowed).toBe(true);
		expect(result.traces[0].reason).toContain("direct permission");
	});

	test("explains wildcard resource match", () => {
		const result = debugCan(config, "admin", "brands:write");
		expect(result.allowed).toBe(true);
		expect(result.traces[0].reason).toContain("resource wildcard");
	});

	test("explains deny rule", () => {
		const result = debugCan(config, "admin", "brands:delete");
		expect(result.allowed).toBe(false);
		expect(result.traces[0].reason).toContain("deny rule");
	});

	test("explains missing permission", () => {
		const result = debugCan(config, "viewer", "members:invite");
		expect(result.allowed).toBe(false);
		expect(result.traces[0].reason).toContain("does not have");
	});

	test("shows effective permissions", () => {
		const result = debugCan(config, "viewer", "workspace:read");
		expect(result.effectivePermissions).toEqual(["workspace:read", "brands:read"]);
	});

	test("shows inherited permissions for admin", () => {
		const result = debugCan(config, "admin", "workspace:read");
		expect(result.allowed).toBe(true);
		expect(result.effectivePermissions).toContain("workspace:read");
	});
});

describe("debugRole", () => {
	test("explains direct role match", () => {
		const result = debugRole(config, "admin", "admin");
		expect(result.allowed).toBe(true);
		expect(result.reason).toContain("Direct role match");
	});

	test("explains hierarchy match", () => {
		const result = debugRole(config, "owner", "admin");
		expect(result.allowed).toBe(true);
		expect(result.reason).toContain("at or above");
	});

	test("explains superAdmin bypass", () => {
		// owner would match via hierarchy first, test with a config where hierarchy is absent
		const flatConfig = defineRoles({
			roles: {
				owner: { permissions: ["*"] },
				admin: { permissions: ["workspace:update"] },
			},
			superAdmin: "owner",
		});
		const result = debugRole(flatConfig, "owner", "admin");
		expect(result.allowed).toBe(true);
		expect(result.reason).toContain("superAdmin");
	});

	test("explains denial with hierarchy info", () => {
		const result = debugRole(config, "viewer", "admin");
		expect(result.allowed).toBe(false);
		expect(result.reason).toContain("below");
	});

	test("explains denial without hierarchy", () => {
		const flatConfig = defineRoles({
			roles: {
				admin: { permissions: ["*"] },
				viewer: { permissions: ["workspace:read"] },
			},
		});
		const result = debugRole(flatConfig, "viewer", "admin");
		expect(result.allowed).toBe(false);
		expect(result.reason).toContain("no hierarchy");
	});
});
