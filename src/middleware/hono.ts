import type { Context, Env, Next } from "hono";
import { createGuard } from "../guard";
import type { AbilityContext, AppAbility, RBACConfig } from "../types";

/** Hono env type that provides typed access to the ability on context */
export interface AegisEnv extends Env {
	Variables: {
		ability: AppAbility;
	};
}

/** Options for creating Hono RBAC middleware */
export interface HonoRBACOptions<TRole extends string = string> {
	/** The RBAC config to use for permission checks */
	config: RBACConfig<TRole>;
	/** Extract the user's role from the Hono context */
	getRole: (c: Context) => TRole | undefined;
	/** Extract the ability context for resolving {{placeholder}} conditions. Optional. */
	getContext?: (c: Context) => AbilityContext | undefined;
	/** Custom handler for 401 Unauthorized. Defaults to JSON response. */
	onUnauthorized?: (c: Context) => Response | Promise<Response>;
	/** Custom handler for 403 Forbidden. Defaults to JSON response. */
	onForbidden?: (c: Context) => Response | Promise<Response>;
}

/**
 * Create Hono middleware for RBAC enforcement.
 *
 * @example
 * ```ts
 * const { requirePermission, requireRole } = createRBACMiddleware({
 *   config: rbacConfig,
 *   getRole: (c) => c.get("workspaceRole"),
 *   getContext: (c) => ({ userId: c.get("userId") }),
 * });
 *
 * // Type-safe access to ability:
 * const app = new Hono<AegisEnv>();
 * app.get("/brands", requirePermission("brands:read"), (c) => {
 *   const ability = c.get("ability"); // typed as AppAbility
 * });
 * ```
 */
export function createRBACMiddleware<TRole extends string>(options: HonoRBACOptions<TRole>) {
	const { config, getRole, getContext } = options;
	const guard = createGuard(config);

	const handleUnauthorized =
		options.onUnauthorized ?? ((c: Context) => c.json({ data: null, error: "Unauthorized" }, 401));
	const handleForbidden =
		options.onForbidden ?? ((c: Context) => c.json({ data: null, error: "Forbidden" }, 403));

	/**
	 * Middleware that checks if the user has specific permissions.
	 * Permission format: "resource:action" (e.g., "brands:write", "members:invite")
	 * All permissions must pass (AND logic).
	 * Throws at startup if called with no permissions.
	 */
	function requirePermission(...permissions: string[]) {
		if (permissions.length === 0) {
			throw new Error(
				"requirePermission requires at least one permission. An empty check would allow all roles through.",
			);
		}

		return async (c: Context, next: Next) => {
			const role = getRole(c);
			if (!role) {
				return handleUnauthorized(c);
			}

			const context = getContext?.(c);
			const { allowed, ability } = context
				? guard.checkPermission(role, context, ...permissions)
				: guard.checkPermission(role, ...permissions);
			c.set("ability", ability);

			if (!allowed) {
				return handleForbidden(c);
			}

			await next();
		};
	}

	/**
	 * Middleware that checks if the user has one of the specified roles.
	 * Respects hierarchy — a higher role passes a check for a lower role.
	 */
	function requireRole(...allowedRoles: TRole[]) {
		return async (c: Context, next: Next) => {
			const role = getRole(c);
			if (!role) {
				return handleUnauthorized(c);
			}

			const { allowed, ability } = guard.checkRole(role, ...allowedRoles);
			c.set("ability", ability);

			if (!allowed) {
				return handleForbidden(c);
			}

			await next();
		};
	}

	return { requirePermission, requireRole };
}
