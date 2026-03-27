import { describe, expect, test } from "bun:test";
import { subject } from "@casl/ability";
import { buildAbility } from "../src/ability";
import { can } from "../src/check";
import { defineRoles } from "../src/define";

const config = defineRoles({
	roles: {
		owner: { permissions: ["*"] },
		editor: {
			permissions: ["posts:read"],
			when: [
				{
					permission: "posts:update",
					conditions: { authorId: "{{userId}}" },
				},
				{
					permission: "posts:delete",
					conditions: { authorId: "{{userId}}" },
				},
			],
		},
		viewer: {
			permissions: ["posts:read"],
		},
	},
	hierarchy: ["owner", "editor", "viewer"],
	superAdmin: "owner",
});

describe("conditional permissions", () => {
	test("editor can read all posts unconditionally", () => {
		expect(can(config, "editor", "posts:read")).toBe(true);
	});

	test("editor has conditional update permission (ability built)", () => {
		const ability = buildAbility(config, "editor");
		// With matching condition
		expect(ability.can("update", subject("posts", { authorId: "{{userId}}" }))).toBe(true);
		// Without matching condition
		expect(ability.can("update", subject("posts", { authorId: "other-user" }))).toBe(false);
	});

	test("viewer cannot update posts at all", () => {
		const ability = buildAbility(config, "viewer");
		expect(ability.can("update", subject("posts", { authorId: "{{userId}}" }))).toBe(false);
	});

	test("superAdmin bypasses conditions", () => {
		const ability = buildAbility(config, "owner");
		expect(ability.can("update", subject("posts", { authorId: "anyone" }))).toBe(true);
	});
});

describe("conditional permissions with hierarchy", () => {
	const hierarchyConfig = defineRoles({
		roles: {
			admin: {
				permissions: ["posts:*"],
			},
			editor: {
				permissions: ["posts:read"],
				when: [{ permission: "posts:update", conditions: { authorId: "user-1" } }],
			},
			viewer: {
				permissions: ["posts:read"],
			},
		},
		hierarchy: ["admin", "editor", "viewer"],
	});

	test("admin inherits editor conditional permissions but also has full access", () => {
		const ability = buildAbility(hierarchyConfig, "admin");
		// admin has posts:* so can update any post
		expect(ability.can("update", subject("posts", { authorId: "anyone" }))).toBe(true);
	});
});

describe("defineRoles validation for when", () => {
	test("throws on invalid permission in when", () => {
		expect(() =>
			defineRoles({
				roles: {
					admin: {
						permissions: ["*"],
						when: [{ permission: ":broken", conditions: { id: "1" } }],
					},
				},
			}),
		).toThrow('Invalid conditional permission ":broken"');
	});

	test("throws on empty conditions", () => {
		expect(() =>
			defineRoles({
				roles: {
					admin: {
						permissions: ["*"],
						when: [{ permission: "posts:update", conditions: {} }],
					},
				},
			}),
		).toThrow("non-empty conditions");
	});

	test("accepts valid conditional permissions", () => {
		expect(() =>
			defineRoles({
				roles: {
					editor: {
						permissions: ["posts:read"],
						when: [{ permission: "posts:update", conditions: { authorId: "user-1" } }],
					},
				},
			}),
		).not.toThrow();
	});
});
