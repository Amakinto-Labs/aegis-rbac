import {
	buildAbility,
	collectConditionalPermissions,
	collectFieldPermissions,
	collectPermissions,
} from "./ability";
import { parsePermission } from "./permission";
import type { AbilityContext, RBACConfig } from "./types";

/**
 * Check if a role has a specific permission.
 *
 * @example
 * ```ts
 * can(config, "admin", "members:invite"); // true
 * can(config, "viewer", "members:invite"); // false
 *
 * // With context for conditional permissions
 * can(config, "editor", "posts:update", { userId: "user-123" }); // checks with resolved conditions
 * ```
 */
export function can<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
	permission: string,
	context?: AbilityContext,
): boolean {
	const ability = buildAbility(config, role, context);
	const { action, subject } = parsePermission(permission);
	return ability.can(action, subject);
}

/**
 * Assert that a role has a specific permission. Throws if unauthorized.
 *
 * @example
 * ```ts
 * authorize(config, "viewer", "members:invite");
 * // throws: Forbidden: role "viewer" cannot "invite" on "members"
 *
 * // With context for conditional permissions
 * authorize(config, "editor", "posts:update", { userId: "user-123" });
 * ```
 */
export function authorize<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
	permission: string,
	context?: AbilityContext,
): void {
	if (!can(config, role, permission, context)) {
		const { action, subject } = parsePermission(permission);
		throw new Error(`Forbidden: role "${role}" cannot "${action}" on "${subject}"`);
	}
}

/** Full permissions summary for a role */
export interface PermissionsSummary {
	/** Standard permissions (deduplicated, including inherited) */
	permissions: string[];
	/** Conditional permissions with their conditions */
	conditionals: Array<{ permission: string; conditions: Record<string, unknown> }>;
	/** Field-level permissions */
	fields: Array<{ permission: string; fields: string[] }>;
	/** Denied permissions */
	denied: string[];
}

/**
 * Get all effective permissions for a role, including conditionals, fields, and denials.
 * Useful for debugging, admin UIs, and displaying "what can this role do?".
 *
 * @example
 * ```ts
 * getPermissions(config, "editor");
 * // {
 * //   permissions: ["posts:read"],
 * //   conditionals: [{ permission: "posts:update", conditions: { authorId: "{{userId}}" } }],
 * //   fields: [],
 * //   denied: []
 * // }
 * ```
 */
export function getPermissions<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
): PermissionsSummary {
	if (config.superAdmin && role === config.superAdmin) {
		return { permissions: ["*"], conditionals: [], fields: [], denied: [] };
	}

	const permissions = [...new Set(collectPermissions(config, role))];

	const conditionals = collectConditionalPermissions(config, role).map((cp) => ({
		permission: cp.permission,
		conditions: cp.conditions,
	}));

	const fields = collectFieldPermissions(config, role).map((fp) => ({
		permission: fp.permission,
		fields: fp.fields,
	}));

	const roleConfig = config.roles[role];
	const denied = roleConfig?.deny ? [...roleConfig.deny] : [];

	return { permissions, conditionals, fields, denied };
}
