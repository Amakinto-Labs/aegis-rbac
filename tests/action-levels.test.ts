import { describe, expect, it } from "bun:test";
import { defineRoles, can, authorize, buildAbility, createGuard, getPermissions, applyOverrides, debugCan } from "../src";

const config = defineRoles({
	actionLevels: ["read", "write", "delete"],
	roles: {
		admin: { permissions: ["posts:delete", "users:delete"] },
		editor: { permissions: ["posts:write", "users:read"] },
		viewer: { permissions: ["posts:read"] },
	},
	hierarchy: ["admin", "editor", "viewer"],
	superAdmin: "admin",
});

describe("action levels", () => {
	describe("basic implication", () => {
		it("write implies read", () => {
			expect(can(config, "editor", "posts:read")).toBe(true);
		});

		it("write does not imply delete", () => {
			expect(can(config, "editor", "posts:delete")).toBe(false);
		});

		it("delete implies write and read", () => {
			const noHierarchy = defineRoles({
				actionLevels: ["read", "write", "delete"],
				roles: {
					admin: { permissions: ["posts:delete"] },
				},
			});
			expect(can(noHierarchy, "admin", "posts:write")).toBe(true);
			expect(can(noHierarchy, "admin", "posts:read")).toBe(true);
		});

		it("read does not imply write or delete", () => {
			expect(can(config, "viewer", "posts:write")).toBe(false);
			expect(can(config, "viewer", "posts:delete")).toBe(false);
		});

		it("exact match still works", () => {
			expect(can(config, "viewer", "posts:read")).toBe(true);
		});
	});

	describe("custom levels", () => {
		it("supports any level names", () => {
			const custom = defineRoles({
				actionLevels: ["none", "reply_only", "full"],
				roles: {
					teacher: { permissions: ["messaging:full"] },
					specialist: { permissions: ["messaging:reply_only"] },
				},
			});

			expect(can(custom, "teacher", "messaging:reply_only")).toBe(true);
			expect(can(custom, "teacher", "messaging:none")).toBe(true);
			expect(can(custom, "specialist", "messaging:full")).toBe(false);
			expect(can(custom, "specialist", "messaging:none")).toBe(true);
		});
	});

	describe("without action levels", () => {
		it("existing behavior unchanged", () => {
			const noLevels = defineRoles({
				roles: {
					editor: { permissions: ["posts:write"] },
				},
			});
			// write does NOT imply read without actionLevels
			expect(can(noLevels, "editor", "posts:read")).toBe(false);
			expect(can(noLevels, "editor", "posts:write")).toBe(true);
		});
	});

	describe("wildcards", () => {
		it("resource:* still grants everything regardless of levels", () => {
			const cfg = defineRoles({
				actionLevels: ["read", "write", "delete"],
				roles: { editor: { permissions: ["posts:*"] } },
			});
			expect(can(cfg, "editor", "posts:read")).toBe(true);
			expect(can(cfg, "editor", "posts:write")).toBe(true);
			expect(can(cfg, "editor", "posts:delete")).toBe(true);
			expect(can(cfg, "editor", "posts:anything")).toBe(true);
		});

		it("* still grants everything", () => {
			const cfg = defineRoles({
				actionLevels: ["read", "write", "delete"],
				roles: { admin: { permissions: ["*"] } },
			});
			expect(can(cfg, "admin", "posts:read")).toBe(true);
			expect(can(cfg, "admin", "any:thing")).toBe(true);
		});
	});

	describe("with role hierarchy", () => {
		it("higher role inherits lower role permissions + action levels stack", () => {
			// admin inherits editor (posts:write) and viewer (posts:read)
			// plus admin's own posts:delete
			// editor inherits viewer's posts:read
			expect(can(config, "editor", "posts:read")).toBe(true); // write implies read + inherited from viewer
			expect(can(config, "admin", "posts:read")).toBe(true);  // superAdmin
		});

		it("action levels work independently per resource", () => {
			// editor has posts:write and users:read
			expect(can(config, "editor", "posts:read")).toBe(true);   // write implies read
			expect(can(config, "editor", "users:read")).toBe(true);   // explicit
			expect(can(config, "editor", "users:write")).toBe(false); // read doesn't imply write
		});
	});

	describe("with deny rules", () => {
		it("deny at a level also denies implied lower levels", () => {
			const cfg = defineRoles({
				actionLevels: ["read", "write", "delete"],
				roles: {
					editor: {
						permissions: ["posts:delete"],
						deny: ["posts:write"], // deny write — implies deny read too
					},
				},
			});
			expect(can(cfg, "editor", "posts:read")).toBe(false);  // write deny covers read
			expect(can(cfg, "editor", "posts:write")).toBe(false);  // explicitly denied
			expect(can(cfg, "editor", "posts:delete")).toBe(true);  // not denied (above write)
		});

		it("deny at a specific level does not deny higher levels", () => {
			const cfg = defineRoles({
				actionLevels: ["read", "write", "delete"],
				roles: {
					editor: {
						permissions: ["posts:delete"],
						deny: ["posts:read"], // only deny read
					},
				},
			});
			expect(can(cfg, "editor", "posts:read")).toBe(false);   // denied
			expect(can(cfg, "editor", "posts:write")).toBe(true);   // not denied
			expect(can(cfg, "editor", "posts:delete")).toBe(true);  // not denied
		});
	});

	describe("with buildAbility", () => {
		it("CASL ability reflects implied permissions", () => {
			const cfg = defineRoles({
				actionLevels: ["read", "write", "delete"],
				roles: { editor: { permissions: ["posts:write"] } },
			});
			const ability = buildAbility(cfg, "editor");
			expect(ability.can("write", "posts")).toBe(true);
			expect(ability.can("read", "posts")).toBe(true);
			expect(ability.can("delete", "posts")).toBe(false);
		});
	});

	describe("with createGuard", () => {
		it("guard checks respect action levels", () => {
			const cfg = defineRoles({
				actionLevels: ["read", "write", "delete"],
				roles: { editor: { permissions: ["posts:write"] } },
			});
			const guard = createGuard(cfg);
			expect(guard.checkPermission("editor", "posts:read").allowed).toBe(true);
			expect(guard.checkPermission("editor", "posts:delete").allowed).toBe(false);
		});
	});

	describe("with applyOverrides", () => {
		it("preserves actionLevels through overrides", () => {
			const overridden = applyOverrides(config, {
				viewer: { permissions: { add: ["comments:write"] } },
			});
			// actionLevels preserved — write implies read
			expect(can(overridden, "viewer", "comments:read")).toBe(true);
			expect(can(overridden, "viewer", "comments:write")).toBe(true);
			expect(can(overridden, "viewer", "comments:delete")).toBe(false);
		});
	});

	describe("with debugCan", () => {
		it("debug shows implied permission", () => {
			const cfg = defineRoles({
				actionLevels: ["read", "write", "delete"],
				roles: { editor: { permissions: ["posts:write"] } },
			});
			const result = debugCan(cfg, "editor", "posts:read");
			expect(result.allowed).toBe(true);
		});
	});

	describe("validation", () => {
		it("throws on duplicate action levels", () => {
			expect(() =>
				defineRoles({
					actionLevels: ["read", "write", "read"],
					roles: { viewer: { permissions: ["posts:read"] } },
				}),
			).toThrow('Duplicate action level "read"');
		});

		it("throws on single action level", () => {
			expect(() =>
				defineRoles({
					actionLevels: ["read"],
					roles: { viewer: { permissions: ["posts:read"] } },
				}),
			).toThrow("at least 2 levels");
		});

		it("allows empty actionLevels (undefined)", () => {
			expect(() =>
				defineRoles({
					roles: { viewer: { permissions: ["posts:read"] } },
				}),
			).not.toThrow();
		});
	});

	describe("actions not in levels", () => {
		it("actions outside actionLevels still work as exact match", () => {
			const cfg = defineRoles({
				actionLevels: ["read", "write", "delete"],
				roles: { editor: { permissions: ["posts:publish"] } },
			});
			expect(can(cfg, "editor", "posts:publish")).toBe(true);
			expect(can(cfg, "editor", "posts:read")).toBe(false); // publish not in levels, no implication
		});
	});
});
