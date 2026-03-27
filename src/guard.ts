import { buildAbility } from "./ability";
import { isRoleAtOrAbove } from "./hierarchy";
import { parsePermission } from "./permission";
import type { AbilityContext, GuardResult, RBACConfig } from "./types";

/**
 * Create a framework-agnostic RBAC guard.
 * Returns pure check functions that work without any HTTP framework.
 * Use this directly for Express, Fastify, Elysia, or any non-Hono framework.
 *
 * @example
 * ```ts
 * const guard = createGuard(rbacConfig);
 *
 * const { allowed, ability } = guard.checkPermission("admin", "brands:write");
 * if (!allowed) throw new Error("Forbidden");
 *
 * // With context for conditional permissions
 * const { allowed } = guard.checkPermission("editor", { userId: "user-123" }, "posts:update");
 * ```
 */
export function createGuard<TRole extends string>(config: RBACConfig<TRole>) {
	return {
		/**
		 * Check if a role has all specified permissions.
		 * Throws if no permissions are provided.
		 *
		 * Overloads:
		 * - checkPermission(role, ...permissions) — no context
		 * - checkPermission(role, context, ...permissions) — with context for conditional perms
		 */
		checkPermission(
			role: TRole,
			contextOrPermission: AbilityContext | string,
			...rest: string[]
		): GuardResult {
			let context: AbilityContext | undefined;
			let permissions: string[];

			if (typeof contextOrPermission === "string") {
				permissions = [contextOrPermission, ...rest];
			} else {
				context = contextOrPermission;
				permissions = rest;
			}

			if (permissions.length === 0) {
				throw new Error(
					"checkPermission requires at least one permission. An empty check would allow all roles through.",
				);
			}

			const ability = buildAbility(config, role, context);
			const allowed = permissions.every((p) => {
				const { action, subject } = parsePermission(p);
				return ability.can(action, subject);
			});
			return { allowed, ability };
		},

		/**
		 * Check if a role matches any of the allowed roles (respects hierarchy and superAdmin).
		 * Returns the result and the CASL ability for downstream use.
		 */
		checkRole(role: TRole, ...allowedRoles: TRole[]): GuardResult {
			const ability = buildAbility(config, role);

			// Direct role match
			if (allowedRoles.includes(role)) {
				return { allowed: true, ability };
			}

			// Hierarchy check
			if (config.hierarchy) {
				const passes = allowedRoles.some((allowedRole) =>
					isRoleAtOrAbove(config, role, allowedRole),
				);
				if (passes) return { allowed: true, ability };
			}

			// Super admin bypass
			if (config.superAdmin && role === config.superAdmin) {
				return { allowed: true, ability };
			}

			return { allowed: false, ability };
		},
	};
}
