import type { RBACConfig, RoleConfig } from "./types";
import { isValidPermission } from "./validate";

/**
 * Recursively freeze an object and all nested objects/arrays.
 */
function deepFreeze<T extends object>(obj: T): T {
	Object.freeze(obj);
	for (const value of Object.values(obj)) {
		if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
			deepFreeze(value);
		}
	}
	return obj;
}

/**
 * Define roles and permissions for a project.
 * Returns a deeply frozen config object used by buildAbility() and middleware.
 * Validates config structure and throws on invalid input.
 *
 * @example
 * ```ts
 * const config = defineRoles({
 *   roles: {
 *     owner: { permissions: ["*"] },
 *     admin: { permissions: ["workspace:update", "members:*"] },
 *     viewer: { permissions: ["workspace:read", "analytics:read"] },
 *   },
 *   hierarchy: ["owner", "admin", "viewer"],
 *   superAdmin: "owner",
 * });
 * ```
 */
export function defineRoles<TRole extends string>(
	config: RBACConfig<TRole> & { roles: Record<TRole, RoleConfig> },
): Readonly<RBACConfig<TRole>> {
	const roleNames = Object.keys(config.roles) as TRole[];

	if (roleNames.length === 0) {
		throw new Error("RBAC config must define at least one role");
	}

	// Validate permissions format (allow, deny, when, fields)
	for (const role of roleNames) {
		const roleConfig = config.roles[role];
		for (const permission of roleConfig.permissions) {
			if (!isValidPermission(permission)) {
				throw new Error(
					`Invalid permission "${permission}" in role "${role}". Use "resource:action", "resource:*", or "*"`,
				);
			}
		}
		if (roleConfig.deny) {
			for (const permission of roleConfig.deny) {
				if (!isValidPermission(permission)) {
					throw new Error(
						`Invalid deny permission "${permission}" in role "${role}". Use "resource:action", "resource:*", or "*"`,
					);
				}
			}
		}
		if (roleConfig.when) {
			for (const cp of roleConfig.when) {
				if (!isValidPermission(cp.permission)) {
					throw new Error(
						`Invalid conditional permission "${cp.permission}" in role "${role}". Use "resource:action", "resource:*", or "*"`,
					);
				}
				if (
					!cp.conditions ||
					typeof cp.conditions !== "object" ||
					Object.keys(cp.conditions).length === 0
				) {
					throw new Error(
						`Conditional permission "${cp.permission}" in role "${role}" must have a non-empty conditions object`,
					);
				}
			}
		}
		if (roleConfig.fields) {
			for (const fp of roleConfig.fields) {
				if (!isValidPermission(fp.permission)) {
					throw new Error(
						`Invalid field permission "${fp.permission}" in role "${role}". Use "resource:action", "resource:*", or "*"`,
					);
				}
				if (!Array.isArray(fp.fields) || fp.fields.length === 0) {
					throw new Error(
						`Field permission "${fp.permission}" in role "${role}" must have a non-empty fields array`,
					);
				}
			}
		}
	}

	// Validate hierarchy
	if (config.hierarchy) {
		// Check for duplicates
		const seen = new Set<TRole>();
		for (const role of config.hierarchy) {
			if (seen.has(role)) {
				throw new Error(`Duplicate role "${role}" in hierarchy`);
			}
			seen.add(role);
		}

		// Check hierarchy references existing roles
		for (const role of config.hierarchy) {
			if (!config.roles[role]) {
				throw new Error(`Hierarchy references unknown role "${role}"`);
			}
		}

		// Check all defined roles are in hierarchy
		for (const role of roleNames) {
			if (!config.hierarchy.includes(role)) {
				throw new Error(
					`Role "${role}" is defined in roles but missing from hierarchy. All roles must be included when hierarchy is provided`,
				);
			}
		}
	}

	// Validate superAdmin references existing role
	if (config.superAdmin && !config.roles[config.superAdmin]) {
		throw new Error(`superAdmin references unknown role "${config.superAdmin}"`);
	}

	return deepFreeze(config);
}
