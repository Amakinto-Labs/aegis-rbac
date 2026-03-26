/**
 * Example: Simple 3-role workspace RBAC
 * Pattern: owner > editor > viewer
 * Use case: Collaborative tools with read/write/admin tiers
 */
import { defineRoles } from "rbac";

export const rbacConfig = defineRoles({
	roles: {
		owner: {
			permissions: ["*"],
		},
		editor: {
			permissions: ["workspace:read", "documents:*", "templates:*", "media:*"],
		},
		viewer: {
			permissions: ["workspace:read", "documents:read", "templates:read", "media:read"],
		},
	},
	hierarchy: ["owner", "editor", "viewer"],
	superAdmin: "owner",
});
