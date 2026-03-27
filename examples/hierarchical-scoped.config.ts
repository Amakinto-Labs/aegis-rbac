/**
 * Example: Hierarchical roles with data scoping
 * Pattern: platform_admin > tenant_admin > staff > member
 * Use case: Multi-tenant platforms where users see different data based on role
 */
import { defineDataScope, defineRoles } from "aegis";

export const rbacConfig = defineRoles({
	roles: {
		platform_admin: {
			permissions: ["*"],
		},
		tenant_admin: {
			permissions: [
				"messaging:*",
				"calendar:*",
				"directory:*",
				"groups:*",
				"meetings:*",
				"payments:*",
				"feed:*",
				"permissions:*",
				"invitations:*",
				"records:*",
			],
		},
		staff: {
			permissions: [
				"messaging:read",
				"messaging:write",
				"calendar:*",
				"directory:read",
				"groups:read",
				"meetings:*",
				"feed:*",
				"records:read",
			],
		},
		member: {
			permissions: [
				"messaging:read",
				"messaging:write",
				"calendar:read",
				"directory:read",
				"groups:read",
				"meetings:read",
				"meetings:book",
				"payments:read",
				"payments:pay",
				"feed:read",
				"records:read",
			],
		},
	},
	hierarchy: ["platform_admin", "tenant_admin", "staff", "member"],
	superAdmin: "platform_admin",
});

/** Data scope types for row-level filtering */
type TenantScope =
	| { type: "platform_admin" }
	| { type: "tenant_admin"; tenantId: string }
	| { type: "staff"; groupIds: string[] }
	| { type: "member"; linkedIds: string[]; groupIds: string[] };

/**
 * Data scope resolvers — each project provides its own DB queries.
 * These are placeholders showing the pattern.
 */
export const dataScopes = defineDataScope<
	"platform_admin" | "tenant_admin" | "staff" | "member",
	TenantScope
>({
	platform_admin: () => ({ type: "platform_admin" }),
	tenant_admin: (ctx) => ({ type: "tenant_admin", tenantId: ctx.tenantId }),
	staff: async (ctx) => ({
		type: "staff",
		// In real app: query staff→group assignments from DB
		groupIds: [],
	}),
	member: async (ctx) => ({
		type: "member",
		// In real app: query member relationships from DB
		linkedIds: [],
		groupIds: [],
	}),
});
