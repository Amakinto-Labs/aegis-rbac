/**
 * Example: 4-role workspace RBAC
 * Pattern: owner > admin > manager > analyst
 * Use case: SaaS platforms with tiered team access
 */
import { defineRoles } from "rbac";

export const rbacConfig = defineRoles({
	roles: {
		owner: {
			permissions: ["*"],
		},
		admin: {
			permissions: [
				"workspace:update",
				"members:invite",
				"members:remove",
				"members:update-role",
				"brands:*",
				"api-keys:*",
				"webhooks:*",
			],
		},
		manager: {
			permissions: ["brands:read", "brands:write", "campaigns:*", "rewards:*", "tiers:*"],
		},
		analyst: {
			permissions: ["brands:read", "analytics:read", "transactions:read", "activities:read"],
		},
	},
	hierarchy: ["owner", "admin", "manager", "analyst"],
	superAdmin: "owner",
});
