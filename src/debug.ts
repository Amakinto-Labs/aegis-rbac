import { collectPermissions } from "./ability";
import { isRoleAtOrAbove } from "./hierarchy";
import { parsePermission } from "./permission";
import type { RBACConfig } from "./types";

/** A single debug trace entry explaining a permission decision */
export interface DebugTrace {
	permission: string;
	allowed: boolean;
	reason: string;
}

/** Full debug result for a permission check */
export interface DebugResult {
	role: string;
	permission: string;
	allowed: boolean;
	traces: DebugTrace[];
	effectivePermissions: string[];
}

/** Full debug result for a role check */
export interface DebugRoleResult {
	userRole: string;
	requiredRoles: string[];
	allowed: boolean;
	reason: string;
}

/**
 * Debug why a permission check passed or failed.
 * Returns a detailed trace of the decision process.
 *
 * @example
 * ```ts
 * const result = debugCan(config, "viewer", "brands:write");
 * // {
 * //   role: "viewer",
 * //   permission: "brands:write",
 * //   allowed: false,
 * //   traces: [
 * //     { permission: "brands:write", allowed: false, reason: 'Role "viewer" does not have "brands:write" or a covering wildcard' }
 * //   ],
 * //   effectivePermissions: ["workspace:read", "brands:read"]
 * // }
 * ```
 */
export function debugCan<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
	permission: string,
): DebugResult {
	const traces: DebugTrace[] = [];
	const effectivePermissions = [...new Set(collectPermissions(config, role))];

	// Super admin bypass
	if (config.superAdmin && role === config.superAdmin) {
		traces.push({
			permission,
			allowed: true,
			reason: `Role "${role}" is superAdmin — bypasses all checks`,
		});
		return { role, permission, allowed: true, traces, effectivePermissions: ["*"] };
	}

	const { action, subject } = parsePermission(permission);

	// Check deny rules
	const roleConfig = config.roles[role];
	if (roleConfig?.deny) {
		for (const deny of roleConfig.deny) {
			const parsed = parsePermission(deny);
			if (
				(parsed.action === action && parsed.subject === subject) ||
				(parsed.action === "manage" && parsed.subject === subject)
			) {
				traces.push({
					permission,
					allowed: false,
					reason: `Denied by explicit deny rule "${deny}" on role "${role}"`,
				});
				return { role, permission, allowed: false, traces, effectivePermissions };
			}
		}
	}

	// Check direct permissions
	for (const perm of effectivePermissions) {
		const parsed = parsePermission(perm);
		if (perm === "*") {
			traces.push({
				permission,
				allowed: true,
				reason: `Granted by wildcard "*" permission`,
			});
			return { role, permission, allowed: true, traces, effectivePermissions };
		}
		if (parsed.action === "manage" && parsed.subject === subject) {
			traces.push({
				permission,
				allowed: true,
				reason: `Granted by resource wildcard "${perm}"`,
			});
			return { role, permission, allowed: true, traces, effectivePermissions };
		}
		if (parsed.action === action && parsed.subject === subject) {
			const isOwn = roleConfig?.permissions.includes(perm);
			traces.push({
				permission,
				allowed: true,
				reason: isOwn
					? `Granted by direct permission "${perm}" on role "${role}"`
					: `Granted by inherited permission "${perm}"`,
			});
			return { role, permission, allowed: true, traces, effectivePermissions };
		}
	}

	// Not found
	traces.push({
		permission,
		allowed: false,
		reason: `Role "${role}" does not have "${permission}" or a covering wildcard`,
	});

	return { role, permission, allowed: false, traces, effectivePermissions };
}

/**
 * Debug why a role check passed or failed.
 *
 * @example
 * ```ts
 * const result = debugRole(config, "viewer", "admin");
 * // {
 * //   userRole: "viewer",
 * //   requiredRoles: ["admin"],
 * //   allowed: false,
 * //   reason: 'Role "viewer" is below "admin" in hierarchy'
 * // }
 * ```
 */
export function debugRole<TRole extends string>(
	config: RBACConfig<TRole>,
	userRole: TRole,
	...requiredRoles: TRole[]
): DebugRoleResult {
	// Direct match
	if (requiredRoles.includes(userRole)) {
		return {
			userRole,
			requiredRoles,
			allowed: true,
			reason: `Direct role match: "${userRole}"`,
		};
	}

	// Hierarchy check
	if (config.hierarchy) {
		for (const required of requiredRoles) {
			if (isRoleAtOrAbove(config, userRole, required)) {
				return {
					userRole,
					requiredRoles,
					allowed: true,
					reason: `Role "${userRole}" is at or above "${required}" in hierarchy`,
				};
			}
		}
	}

	// Super admin bypass
	if (config.superAdmin && userRole === config.superAdmin) {
		return {
			userRole,
			requiredRoles,
			allowed: true,
			reason: `Role "${userRole}" is superAdmin — bypasses role checks`,
		};
	}

	// Denied
	const reasons: string[] = [];
	if (!config.hierarchy) {
		reasons.push("no hierarchy defined");
	} else {
		for (const required of requiredRoles) {
			reasons.push(`"${userRole}" is below "${required}" in hierarchy`);
		}
	}

	return {
		userRole,
		requiredRoles,
		allowed: false,
		reason: `Denied: ${reasons.join("; ")}`,
	};
}
