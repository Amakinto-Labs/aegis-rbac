import { describe, expect, test } from "bun:test";
import { subject } from "@casl/ability";
import { defineRoles } from "../src/define";
import { createGuard } from "../src/guard";

const config = defineRoles({
	roles: {
		owner: { permissions: ["*"] },
		admin: { permissions: ["workspace:update", "members:invite", "brands:*"] },
		editor: {
			permissions: ["posts:read"],
			when: [{ permission: "posts:update", conditions: { authorId: "{{userId}}" } }],
		},
		viewer: { permissions: ["workspace:read", "brands:read"] },
	},
	hierarchy: ["owner", "admin", "editor", "viewer"],
	superAdmin: "owner",
});

describe("createGuard", () => {
	const guard = createGuard(config);

	describe("checkPermission", () => {
		test("returns allowed:true for valid permission", () => {
			const result = guard.checkPermission("admin", "brands:read");
			expect(result.allowed).toBe(true);
		});

		test("returns allowed:false for invalid permission", () => {
			const result = guard.checkPermission("viewer", "brands:write");
			expect(result.allowed).toBe(false);
		});

		test("checks all permissions (AND logic)", () => {
			const result = guard.checkPermission("viewer", "brands:read", "workspace:update");
			expect(result.allowed).toBe(false);
		});

		test("returns ability for downstream use", () => {
			const { ability } = guard.checkPermission("admin", "brands:read");
			expect(ability.can("update", "workspace")).toBe(true);
			expect(ability.can("delete", "workspace")).toBe(false);
		});

		test("throws on empty permissions", () => {
			expect(() => guard.checkPermission("admin")).toThrow("requires at least one permission");
		});
	});

	describe("checkPermission with context", () => {
		test("resolves conditional permissions with context", () => {
			const { allowed, ability } = guard.checkPermission(
				"editor",
				{ userId: "user-123" },
				"posts:update",
			);
			expect(allowed).toBe(true);
			expect(ability.can("update", subject("posts", { authorId: "user-123" }))).toBe(true);
			expect(ability.can("update", subject("posts", { authorId: "other" }))).toBe(false);
		});

		test("context does not affect non-conditional permissions", () => {
			const { allowed } = guard.checkPermission("admin", { userId: "user-123" }, "brands:read");
			expect(allowed).toBe(true);
		});
	});

	describe("checkRole", () => {
		test("allows direct role match", () => {
			const result = guard.checkRole("admin", "admin");
			expect(result.allowed).toBe(true);
		});

		test("rejects non-matching role", () => {
			const result = guard.checkRole("viewer", "admin");
			expect(result.allowed).toBe(false);
		});

		test("respects hierarchy — higher role passes lower check", () => {
			const result = guard.checkRole("owner", "admin");
			expect(result.allowed).toBe(true);
		});

		test("respects hierarchy — lower role fails higher check", () => {
			const result = guard.checkRole("viewer", "admin");
			expect(result.allowed).toBe(false);
		});

		test("respects superAdmin bypass", () => {
			const result = guard.checkRole("owner", "viewer");
			expect(result.allowed).toBe(true);
		});

		test("returns ability for downstream use", () => {
			const { ability } = guard.checkRole("admin", "admin");
			expect(ability.can("invite", "members")).toBe(true);
		});
	});

	describe("without hierarchy or superAdmin", () => {
		const flatConfig = defineRoles({
			roles: {
				admin: { permissions: ["workspace:update"] },
				viewer: { permissions: ["workspace:read"] },
			},
		});
		const flatGuard = createGuard(flatConfig);

		test("only direct role match works", () => {
			expect(flatGuard.checkRole("admin", "admin").allowed).toBe(true);
			expect(flatGuard.checkRole("admin", "viewer").allowed).toBe(false);
			expect(flatGuard.checkRole("viewer", "admin").allowed).toBe(false);
		});
	});
});
