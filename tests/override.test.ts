import { describe, expect, it } from "bun:test";
import { defineRoles, applyOverrides, can, authorize, getPermissions, buildAbility, createGuard } from "../src";
import type { RBACConfig } from "../src";

const base = defineRoles({
	roles: {
		owner: { permissions: ["*"] },
		admin: {
			permissions: ["workspace:update", "members:*", "brands:read"],
			deny: ["billing:delete"],
		},
		editor: {
			permissions: ["brands:read", "brands:write"],
			when: [{ permission: "posts:update", conditions: { authorId: "{{userId}}" } }],
			fields: [{ permission: "users:read", fields: ["name", "email"] }],
		},
		viewer: { permissions: ["workspace:read", "brands:read"] },
	},
	hierarchy: ["owner", "admin", "editor", "viewer"],
	superAdmin: "owner",
});

describe("applyOverrides", () => {
	describe("permissions", () => {
		it("adds permissions to a role", () => {
			const config = applyOverrides(base, {
				viewer: { permissions: { add: ["analytics:read"] } },
			});
			expect(can(config, "viewer", "analytics:read")).toBe(true);
			expect(can(config, "viewer", "workspace:read")).toBe(true); // original preserved
		});

		it("removes permissions from a role", () => {
			const config = applyOverrides(base, {
				admin: { permissions: { remove: ["members:*"] } },
			});
			expect(can(config, "admin", "members:invite")).toBe(false);
			expect(can(config, "admin", "workspace:update")).toBe(true); // others preserved
		});

		it("adds and removes in one override", () => {
			const config = applyOverrides(base, {
				editor: {
					permissions: { add: ["analytics:read"], remove: ["brands:write"] },
				},
			});
			expect(can(config, "editor", "analytics:read")).toBe(true);
			expect(can(config, "editor", "brands:write")).toBe(false);
			expect(can(config, "editor", "brands:read")).toBe(true);
		});
	});

	describe("deny rules", () => {
		it("adds deny rules to a role", () => {
			const config = applyOverrides(base, {
				editor: { deny: { add: ["brands:delete"] } },
			});
			const perms = getPermissions(config, "editor");
			expect(perms.denied).toContain("brands:delete");
		});

		it("removes deny rules from a role", () => {
			const config = applyOverrides(base, {
				admin: { deny: { remove: ["billing:delete"] } },
			});
			const perms = getPermissions(config, "admin");
			expect(perms.denied).not.toContain("billing:delete");
		});

		it("adds deny to a role that had none", () => {
			const config = applyOverrides(base, {
				viewer: { deny: { add: ["workspace:delete"] } },
			});
			const perms = getPermissions(config, "viewer");
			expect(perms.denied).toContain("workspace:delete");
		});
	});

	describe("conditional permissions", () => {
		it("adds conditional permissions", () => {
			const config = applyOverrides(base, {
				viewer: {
					when: {
						add: [{ permission: "comments:update", conditions: { authorId: "{{userId}}" } }],
					},
				},
			});
			const perms = getPermissions(config, "viewer");
			expect(perms.conditionals).toContainEqual({
				permission: "comments:update",
				conditions: { authorId: "{{userId}}" },
			});
		});

		it("removes conditional permissions by permission string", () => {
			const config = applyOverrides(base, {
				editor: { when: { remove: ["posts:update"] } },
			});
			const perms = getPermissions(config, "editor");
			expect(perms.conditionals.find((c) => c.permission === "posts:update")).toBeUndefined();
		});
	});

	describe("field permissions", () => {
		it("adds field permissions", () => {
			const config = applyOverrides(base, {
				viewer: {
					fields: { add: [{ permission: "users:read", fields: ["name"] }] },
				},
			});
			const perms = getPermissions(config, "viewer");
			expect(perms.fields).toContainEqual({ permission: "users:read", fields: ["name"] });
		});

		it("removes field permissions by permission string", () => {
			const config = applyOverrides(base, {
				editor: { fields: { remove: ["users:read"] } },
			});
			const perms = getPermissions(config, "editor");
			expect(perms.fields.find((f) => f.permission === "users:read")).toBeUndefined();
		});
	});

	describe("multiple roles", () => {
		it("overrides multiple roles at once", () => {
			const config = applyOverrides(base, {
				admin: { permissions: { remove: ["members:*"] } },
				viewer: { permissions: { add: ["analytics:read"] } },
			});
			expect(can(config, "admin", "members:invite")).toBe(false);
			expect(can(config, "viewer", "analytics:read")).toBe(true);
		});

		it("roles without overrides are unchanged", () => {
			const config = applyOverrides(base, {
				viewer: { permissions: { add: ["analytics:read"] } },
			});
			// editor unchanged
			expect(can(config, "editor", "brands:read")).toBe(true);
			expect(can(config, "editor", "brands:write")).toBe(true);
		});
	});

	describe("immutability", () => {
		it("does not modify the base config", () => {
			const originalPerms = [...base.roles.viewer.permissions];
			applyOverrides(base, {
				viewer: { permissions: { add: ["analytics:read"] } },
			});
			expect(base.roles.viewer.permissions).toEqual(originalPerms);
		});

		it("returns a deeply frozen config", () => {
			const config = applyOverrides(base, {
				viewer: { permissions: { add: ["analytics:read"] } },
			});
			expect(Object.isFrozen(config)).toBe(true);
			expect(Object.isFrozen(config.roles)).toBe(true);
			expect(Object.isFrozen(config.roles.viewer)).toBe(true);
			expect(Object.isFrozen(config.roles.viewer.permissions)).toBe(true);
		});

		it("returns a new config object reference", () => {
			const config = applyOverrides(base, {});
			expect(config).not.toBe(base);
		});
	});

	describe("integration", () => {
		it("works with can()", () => {
			const config = applyOverrides(base, {
				viewer: { permissions: { add: ["analytics:read"] } },
			});
			expect(can(config, "viewer", "analytics:read")).toBe(true);
			expect(can(config, "viewer", "analytics:write")).toBe(false);
		});

		it("works with authorize()", () => {
			const config = applyOverrides(base, {
				admin: { permissions: { remove: ["members:*"] } },
			});
			expect(() => authorize(config, "admin", "members:invite")).toThrow();
		});

		it("works with buildAbility()", () => {
			const config = applyOverrides(base, {
				editor: { permissions: { add: ["analytics:read"] } },
			});
			const ability = buildAbility(config, "editor");
			expect(ability.can("read", "analytics")).toBe(true);
		});

		it("works with createGuard()", () => {
			const config = applyOverrides(base, {
				viewer: { permissions: { add: ["analytics:read"] } },
			});
			const guard = createGuard(config);
			const result = guard.checkPermission("viewer", "analytics:read");
			expect(result.allowed).toBe(true);
		});

		it("hierarchy still works after override", () => {
			const config = applyOverrides(base, {
				viewer: { permissions: { add: ["analytics:read"] } },
			});
			// admin inherits from editor and viewer — should also get analytics:read
			expect(can(config, "admin", "analytics:read")).toBe(true);
		});

		it("superAdmin still bypasses everything", () => {
			const config = applyOverrides(base, {
				owner: { deny: { add: ["everything:*"] } },
			});
			expect(can(config, "owner", "everything:manage")).toBe(true);
		});
	});

	describe("validation", () => {
		it("throws when override references unknown role", () => {
			expect(() =>
				applyOverrides(base, {
					unknown: { permissions: { add: ["read:stuff"] } },
				} as any),
			).toThrow('Override references unknown role "unknown"');
		});

		it("throws when added permission has invalid format", () => {
			expect(() =>
				applyOverrides(base, {
					viewer: { permissions: { add: [":bad"] } },
				}),
			).toThrow("Invalid permission");
		});

		it("throws when added deny has invalid format", () => {
			expect(() =>
				applyOverrides(base, {
					viewer: { deny: { add: ["a:b:c"] } },
				}),
			).toThrow("Invalid deny permission");
		});
	});

	describe("edge cases", () => {
		it("empty overrides return a valid clone", () => {
			const config = applyOverrides(base, {});
			expect(can(config, "viewer", "workspace:read")).toBe(true);
			expect(Object.isFrozen(config)).toBe(true);
		});

		it("empty add/remove arrays are no-ops", () => {
			const config = applyOverrides(base, {
				viewer: { permissions: { add: [], remove: [] } },
			});
			expect(can(config, "viewer", "workspace:read")).toBe(true);
		});

		it("removing a permission that does not exist is a no-op", () => {
			const config = applyOverrides(base, {
				viewer: { permissions: { remove: ["nonexistent:perm"] } },
			});
			expect(can(config, "viewer", "workspace:read")).toBe(true);
		});

		it("override with only deny changes keeps permissions intact", () => {
			const config = applyOverrides(base, {
				editor: { deny: { add: ["brands:delete"] } },
			});
			expect(can(config, "editor", "brands:read")).toBe(true);
			expect(can(config, "editor", "brands:write")).toBe(true);
		});
	});
});
