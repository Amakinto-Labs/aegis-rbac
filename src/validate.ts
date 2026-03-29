import type { RBACConfig, RoleConfig } from "./types";

/**
 * Validate a permission string format.
 * Valid: "*", "resource", "resource:action", "resource:*"
 * Invalid: "", ":", ":read", "brands:", "a:b:c", "*:read", "*:*"
 */
export function isValidPermission(permission: string): boolean {
	if (permission === "*") return true;
	if (permission.length === 0) return false;
	if (permission.startsWith(":") || permission.endsWith(":")) return false;
	const parts = permission.split(":");
	if (parts.length > 2) return false;
	if (!parts.every((p) => p.length > 0)) return false;
	// Subject (resource) cannot be "*" — use standalone "*" for global wildcard
	if (parts[0] === "*") return false;
	return true;
}

/**
 * Recursively freeze an object and all nested objects/arrays.
 */
export function deepFreeze<T extends object>(obj: T): T {
	Object.freeze(obj);
	for (const value of Object.values(obj)) {
		if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
			deepFreeze(value);
		}
	}
	return obj;
}

/**
 * Validate an RBAC config structure.
 * Throws on invalid input — same rules as defineRoles().
 */
export function validateConfig<TRole extends string>(config: RBACConfig<TRole>): void {
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
		const seen = new Set<TRole>();
		for (const role of config.hierarchy) {
			if (seen.has(role)) {
				throw new Error(`Duplicate role "${role}" in hierarchy`);
			}
			seen.add(role);
		}
		for (const role of config.hierarchy) {
			if (!config.roles[role]) {
				throw new Error(`Hierarchy references unknown role "${role}"`);
			}
		}
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
}
