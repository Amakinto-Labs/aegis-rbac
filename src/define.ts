import type { RBACConfig, RoleConfig } from "./types";
import { validateConfig, deepFreeze } from "./validate";

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
	validateConfig(config);
	return deepFreeze(config);
}
