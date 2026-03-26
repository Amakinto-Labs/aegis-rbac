import { describe, expect, test } from "bun:test";
import { defineRoles } from "../src/define";
import { defineDataScope, resolveScope } from "../src/scope";

type Scope =
	| { type: "admin"; tenantId: string | undefined }
	| { type: "teacher"; classIds: string[] }
	| { type: "parent"; childIds: string[] };

const scopes = defineDataScope<"admin" | "teacher" | "parent", Scope>({
	admin: (ctx) => ({ type: "admin", tenantId: ctx.tenantId }),
	teacher: async (ctx) => ({
		type: "teacher",
		classIds: [`class-for-${ctx.userId}`],
	}),
	parent: async (ctx) => ({
		type: "parent",
		childIds: [`child-of-${ctx.userId}`],
	}),
});

describe("defineDataScope", () => {
	test("freezes the config", () => {
		expect(Object.isFrozen(scopes)).toBe(true);
	});
});

describe("resolveScope", () => {
	test("resolves admin scope synchronously", async () => {
		const scope = await resolveScope(scopes, {
			userId: "user-1",
			tenantId: "school-1",
			role: "admin",
		});
		expect(scope).toEqual({ type: "admin", tenantId: "school-1" });
	});

	test("resolves teacher scope asynchronously", async () => {
		const scope = await resolveScope(scopes, {
			userId: "teacher-1",
			tenantId: "school-1",
			role: "teacher",
		});
		expect(scope).toEqual({ type: "teacher", classIds: ["class-for-teacher-1"] });
	});

	test("resolves parent scope asynchronously", async () => {
		const scope = await resolveScope(scopes, {
			userId: "parent-1",
			tenantId: "school-1",
			role: "parent",
		});
		expect(scope).toEqual({ type: "parent", childIds: ["child-of-parent-1"] });
	});

	test("throws when no resolver exists for role", async () => {
		expect(
			resolveScope(scopes, {
				userId: "user-1",
				tenantId: "school-1",
				role: "unknown" as any,
			}),
		).rejects.toThrow('No scope resolver for role "unknown"');
	});

	test("returns defaultScope when no resolver exists", async () => {
		const scope = await resolveScope(
			scopes,
			{
				userId: "user-1",
				tenantId: "school-1",
				role: "unknown" as any,
			},
			{ defaultScope: null as any },
		);
		expect(scope).toBeNull();
	});

	test("works without tenantId", async () => {
		const scope = await resolveScope(scopes, {
			userId: "user-1",
			role: "admin",
		});
		expect(scope).toEqual({ type: "admin", tenantId: undefined });
	});
});

describe("defineDataScope with rbacConfig validation", () => {
	const rbacConfig = defineRoles({
		roles: {
			admin: { permissions: ["*"] },
			viewer: { permissions: ["workspace:read"] },
		},
	});

	test("accepts scope with valid roles", () => {
		expect(() =>
			defineDataScope(
				{
					admin: () => ({ type: "admin" }),
					viewer: () => ({ type: "viewer" }),
				},
				{ rbacConfig },
			),
		).not.toThrow();
	});

	test("throws when scope defines resolver for unknown role", () => {
		expect(() =>
			defineDataScope(
				{
					admin: () => ({ type: "admin" }),
					manager: () => ({ type: "manager" }),
				} as any,
				{ rbacConfig },
			),
		).toThrow('Scope defines resolver for unknown role "manager"');
	});

	test("works without rbacConfig (no validation)", () => {
		expect(() =>
			defineDataScope({
				anything: () => ({ type: "anything" }),
			}),
		).not.toThrow();
	});
});
