import { describe, expect, test } from "bun:test";
import { buildAbility } from "../src/ability";
import { authorize, can, getPermissions } from "../src/check";
import { defineRoles } from "../src/define";

const config = defineRoles({
	roles: {
		owner: { permissions: ["*"] },
		admin: {
			permissions: ["workspace:update", "members:invite", "members:remove", "brands:*"],
		},
		manager: {
			permissions: ["brands:read", "brands:write", "campaigns:*"],
		},
		analyst: {
			permissions: ["brands:read", "analytics:read"],
		},
	},
	hierarchy: ["owner", "admin", "manager", "analyst"],
	superAdmin: "owner",
});

describe("buildAbility", () => {
	test("super admin can do everything", () => {
		const ability = buildAbility(config, "owner");
		expect(ability.can("manage", "all")).toBe(true);
		expect(ability.can("delete", "workspace")).toBe(true);
		expect(ability.can("read", "anything")).toBe(true);
	});

	test("admin has own permissions", () => {
		const ability = buildAbility(config, "admin");
		expect(ability.can("update", "workspace")).toBe(true);
		expect(ability.can("invite", "members")).toBe(true);
		expect(ability.can("manage", "brands")).toBe(true);
	});

	test("admin inherits from manager and analyst via hierarchy", () => {
		const ability = buildAbility(config, "admin");
		expect(ability.can("read", "analytics")).toBe(true);
		expect(ability.can("manage", "campaigns")).toBe(true);
	});

	test("manager has own permissions", () => {
		const ability = buildAbility(config, "manager");
		expect(ability.can("read", "brands")).toBe(true);
		expect(ability.can("write", "brands")).toBe(true);
		expect(ability.can("manage", "campaigns")).toBe(true);
	});

	test("manager inherits from analyst", () => {
		const ability = buildAbility(config, "manager");
		expect(ability.can("read", "analytics")).toBe(true);
	});

	test("manager cannot access admin-only permissions", () => {
		const ability = buildAbility(config, "manager");
		expect(ability.can("update", "workspace")).toBe(false);
		expect(ability.can("invite", "members")).toBe(false);
	});

	test("analyst has only read access", () => {
		const ability = buildAbility(config, "analyst");
		expect(ability.can("read", "brands")).toBe(true);
		expect(ability.can("read", "analytics")).toBe(true);
		expect(ability.can("write", "brands")).toBe(false);
		expect(ability.can("manage", "campaigns")).toBe(false);
	});

	test("unknown role gets empty permissions", () => {
		const ability = buildAbility(config, "nonexistent" as any);
		expect(ability.can("read", "brands")).toBe(false);
		expect(ability.can("manage", "all")).toBe(false);
	});
});

describe("buildAbility caching", () => {
	test("returns same instance for same config+role", () => {
		const a = buildAbility(config, "admin");
		const b = buildAbility(config, "admin");
		expect(a).toBe(b);
	});

	test("returns different instances for different roles", () => {
		const admin = buildAbility(config, "admin");
		const viewer = buildAbility(config, "analyst");
		expect(admin).not.toBe(viewer);
	});

	test("caches independently per config", () => {
		const config2 = defineRoles({
			roles: {
				admin: { permissions: ["workspace:read"] },
				viewer: { permissions: ["brands:read"] },
			},
		});
		const a = buildAbility(config, "admin");
		const b = buildAbility(config2, "admin");
		expect(a).not.toBe(b);
	});
});

describe("can()", () => {
	test("checks permission with resource:action format", () => {
		expect(can(config, "admin", "members:invite")).toBe(true);
		expect(can(config, "analyst", "members:invite")).toBe(false);
	});

	test("checks wildcard permissions", () => {
		expect(can(config, "owner", "*")).toBe(true);
		expect(can(config, "admin", "brands:*")).toBe(true);
		expect(can(config, "analyst", "brands:*")).toBe(false);
	});

	test("checks resource-only permission", () => {
		expect(can(config, "admin", "brands")).toBe(true);
		expect(can(config, "analyst", "campaigns")).toBe(false);
	});
});

describe("authorize()", () => {
	test("does not throw for allowed permission", () => {
		expect(() => authorize(config, "admin", "members:invite")).not.toThrow();
	});

	test("throws for denied permission", () => {
		expect(() => authorize(config, "analyst", "members:invite")).toThrow(
			'Forbidden: role "analyst" cannot "invite" on "members"',
		);
	});

	test("throws with correct message for wildcard denial", () => {
		expect(() => authorize(config, "analyst", "*")).toThrow(
			'Forbidden: role "analyst" cannot "manage" on "all"',
		);
	});

	test("throws with correct message for resource-only denial", () => {
		expect(() => authorize(config, "analyst", "campaigns")).toThrow(
			'Forbidden: role "analyst" cannot "manage" on "campaigns"',
		);
	});
});

describe("config without hierarchy", () => {
	const flatConfig = defineRoles({
		roles: {
			admin: { permissions: ["workspace:update", "members:invite"] },
			viewer: { permissions: ["workspace:read"] },
		},
	});

	test("roles do not inherit without hierarchy", () => {
		expect(can(flatConfig, "admin", "workspace:update")).toBe(true);
		expect(can(flatConfig, "admin", "workspace:read")).toBe(false);
	});
});

describe("config without superAdmin", () => {
	const noSuperConfig = defineRoles({
		roles: {
			owner: { permissions: ["workspace:*"] },
			viewer: { permissions: ["workspace:read"] },
		},
	});

	test("owner only has defined permissions, not manage all", () => {
		expect(can(noSuperConfig, "owner", "workspace:update")).toBe(true);
		expect(can(noSuperConfig, "owner", "members:invite")).toBe(false);
	});
});

describe("deny rules", () => {
	const denyConfig = defineRoles({
		roles: {
			owner: { permissions: ["*"] },
			admin: {
				permissions: ["brands:*"],
				deny: ["brands:delete"],
			},
			viewer: {
				permissions: ["brands:read"],
			},
		},
		hierarchy: ["owner", "admin", "viewer"],
		superAdmin: "owner",
	});

	test("deny overrides a granted wildcard permission", () => {
		expect(can(denyConfig, "admin", "brands:read")).toBe(true);
		expect(can(denyConfig, "admin", "brands:write")).toBe(true);
		expect(can(denyConfig, "admin", "brands:delete")).toBe(false);
	});

	test("deny does not propagate up hierarchy", () => {
		// owner is superAdmin, should not be affected by admin's deny
		expect(can(denyConfig, "owner", "brands:delete")).toBe(true);
	});

	test("superAdmin ignores deny rules", () => {
		const ability = buildAbility(denyConfig, "owner");
		expect(ability.can("delete", "brands")).toBe(true);
		expect(ability.can("manage", "all")).toBe(true);
	});

	test("deny works with wildcard grant", () => {
		const cfg = defineRoles({
			roles: {
				admin: { permissions: ["*"], deny: ["workspace:delete"] },
			},
		});
		expect(can(cfg, "admin", "workspace:read")).toBe(true);
		expect(can(cfg, "admin", "workspace:delete")).toBe(false);
		expect(can(cfg, "admin", "brands:write")).toBe(true);
	});

	test("deny overrides inherited permission", () => {
		const cfg = defineRoles({
			roles: {
				manager: {
					permissions: ["campaigns:*"],
					deny: ["brands:read"],
				},
				analyst: {
					permissions: ["brands:read", "analytics:read"],
				},
			},
			hierarchy: ["manager", "analyst"],
		});
		// manager inherits brands:read from analyst but denies it
		expect(can(cfg, "manager", "brands:read")).toBe(false);
		// manager still has campaigns and inherited analytics
		expect(can(cfg, "manager", "campaigns:write")).toBe(true);
		expect(can(cfg, "manager", "analytics:read")).toBe(true);
	});
});

describe("getPermissions()", () => {
	test("returns full summary for a role", () => {
		const summary = getPermissions(config, "analyst");
		expect(summary.permissions).toEqual(["brands:read", "analytics:read"]);
		expect(summary.conditionals).toEqual([]);
		expect(summary.fields).toEqual([]);
		expect(summary.denied).toEqual([]);
	});

	test("includes inherited permissions", () => {
		const summary = getPermissions(config, "manager");
		expect(summary.permissions).toContain("brands:read");
		expect(summary.permissions).toContain("campaigns:*");
		expect(summary.permissions).toContain("analytics:read");
	});

	test("deduplicates inherited permissions", () => {
		const summary = getPermissions(config, "manager");
		const brandsReadCount = summary.permissions.filter((p) => p === "brands:read").length;
		expect(brandsReadCount).toBe(1);
	});

	test("returns [*] for superAdmin", () => {
		const summary = getPermissions(config, "owner");
		expect(summary.permissions).toEqual(["*"]);
		expect(summary.conditionals).toEqual([]);
	});

	test("includes conditionals and fields in summary", () => {
		const cfg = defineRoles({
			roles: {
				editor: {
					permissions: ["posts:read"],
					when: [{ permission: "posts:update", conditions: { authorId: "{{userId}}" } }],
					fields: [{ permission: "posts:read", fields: ["title", "body"] }],
					deny: ["posts:delete"],
				},
			},
		});
		const summary = getPermissions(cfg, "editor");
		expect(summary.permissions).toEqual(["posts:read"]);
		expect(summary.conditionals).toEqual([
			{ permission: "posts:update", conditions: { authorId: "{{userId}}" } },
		]);
		expect(summary.fields).toEqual([{ permission: "posts:read", fields: ["title", "body"] }]);
		expect(summary.denied).toEqual(["posts:delete"]);
	});
});
