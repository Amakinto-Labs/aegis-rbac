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

describe("conditional permissions with context", () => {
	test("editor can read all posts unconditionally", () => {
		expect(can(config, "editor", "posts:read")).toBe(true);
	});

	test("editor can update own posts when context resolves", () => {
		const ability = buildAbility(config, "editor", { userId: "user-123" });
		// Matches — authorId resolved to "user-123"
		expect(ability.can("update", subject("posts", { authorId: "user-123" }))).toBe(true);
		// Does not match — different user
		expect(ability.can("update", subject("posts", { authorId: "other-user" }))).toBe(false);
	});

	test("editor can delete own posts when context resolves", () => {
		const ability = buildAbility(config, "editor", { userId: "user-456" });
		expect(ability.can("delete", subject("posts", { authorId: "user-456" }))).toBe(true);
		expect(ability.can("delete", subject("posts", { authorId: "other" }))).toBe(false);
	});

	test("can() with context resolves conditional permissions", () => {
		// can() without context — conditional perm exists but placeholder is literal
		expect(can(config, "editor", "posts:update")).toBe(true);
		// can() with context — same behavior, resolved
		expect(can(config, "editor", "posts:update", { userId: "user-123" })).toBe(true);
	});

	test("viewer cannot update posts even with context", () => {
		const ability = buildAbility(config, "viewer", { userId: "user-123" });
		expect(ability.can("update", subject("posts", { authorId: "user-123" }))).toBe(false);
	});

	test("superAdmin bypasses conditions", () => {
		const ability = buildAbility(config, "owner", { userId: "anyone" });
		expect(ability.can("update", subject("posts", { authorId: "anyone" }))).toBe(true);
		expect(ability.can("update", subject("posts", { authorId: "other" }))).toBe(true);
	});

	test("throws on missing placeholder key in context", () => {
		expect(() => buildAbility(config, "editor", { tenantId: "t1" })).toThrow(
			'placeholder "{{userId}}" not found in context',
		);
	});

	test("without context, placeholders remain literal", () => {
		const ability = buildAbility(config, "editor");
		// Literal "{{userId}}" is the condition — only matches the literal string
		expect(ability.can("update", subject("posts", { authorId: "{{userId}}" }))).toBe(true);
		expect(ability.can("update", subject("posts", { authorId: "user-123" }))).toBe(false);
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
				when: [{ permission: "posts:update", conditions: { authorId: "{{userId}}" } }],
			},
			viewer: {
				permissions: ["posts:read"],
			},
		},
		hierarchy: ["admin", "editor", "viewer"],
	});

	test("admin has full access via wildcard regardless of conditions", () => {
		const ability = buildAbility(hierarchyConfig, "admin", { userId: "user-1" });
		expect(ability.can("update", subject("posts", { authorId: "anyone" }))).toBe(true);
	});
});

describe("placeholder resolution", () => {
	test("throws on missing context key", () => {
		expect(() => buildAbility(config, "editor", { tenantId: "t1" })).toThrow(
			'placeholder "{{userId}}" not found in context',
		);
	});

	test("non-placeholder strings pass through unchanged", () => {
		const staticConfig = defineRoles({
			roles: {
				editor: {
					permissions: ["posts:read"],
					when: [{ permission: "posts:update", conditions: { status: "draft" } }],
				},
			},
		});
		const ability = buildAbility(staticConfig, "editor", { userId: "user-1" });
		expect(ability.can("update", subject("posts", { status: "draft" }))).toBe(true);
		expect(ability.can("update", subject("posts", { status: "published" }))).toBe(false);
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
