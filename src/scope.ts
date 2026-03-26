import type {
	DataScopeConfig,
	RBACConfig,
	ResolveScopeOptions,
	ScopeContext,
	ScopeResolver,
} from "./types";

/**
 * Define data scope resolvers for each role.
 * Optionally validates that scope roles match an RBAC config.
 * Used by projects that need row-level data filtering based on user relationships.
 *
 * @example
 * ```ts
 * const scopes = defineDataScope({
 *   tenant_admin: (ctx) => ({ type: "tenant_admin", tenantId: ctx.tenantId }),
 *   staff: async (ctx) => ({
 *     type: "staff",
 *     groupIds: await getStaffGroups(ctx.userId),
 *   }),
 * });
 *
 * // With RBAC config validation:
 * const scopes = defineDataScope(scopeConfig, { rbacConfig });
 * ```
 */
export function defineDataScope<TRole extends string, TScope>(
	config: DataScopeConfig<TRole, TScope>,
	options?: { rbacConfig: RBACConfig<TRole> },
): DataScopeConfig<TRole, TScope> {
	if (options?.rbacConfig) {
		const rbacRoles = Object.keys(options.rbacConfig.roles) as TRole[];
		const scopeRoles = Object.keys(config) as TRole[];
		for (const role of scopeRoles) {
			if (!rbacRoles.includes(role)) {
				throw new Error(
					`Scope defines resolver for unknown role "${role}". Valid roles: ${rbacRoles.join(", ")}`,
				);
			}
		}
	}
	return Object.freeze(config);
}

/**
 * Resolve the data scope for a user based on their role.
 * Throws if no scope resolver is defined for the role (unless defaultScope is provided).
 *
 * @example
 * ```ts
 * const scope = await resolveScope(scopes, {
 *   userId: "user-123",
 *   tenantId: "tenant-456",
 *   role: "staff",
 * });
 * // { type: "staff", groupIds: ["group-1", "group-2"] }
 *
 * // With default scope for unhandled roles:
 * const scope = await resolveScope(scopes, ctx, { defaultScope: null });
 * ```
 */
export async function resolveScope<TRole extends string, TScope>(
	config: DataScopeConfig<TRole, TScope>,
	ctx: ScopeContext<TRole>,
	options?: ResolveScopeOptions<TScope>,
): Promise<TScope> {
	const resolver = config[ctx.role] as ScopeResolver<TScope, TRole> | undefined;
	if (!resolver) {
		if (options && "defaultScope" in options) {
			return options.defaultScope as TScope;
		}
		throw new Error(
			`No scope resolver for role "${ctx.role}". Define a resolver or provide a defaultScope`,
		);
	}
	return resolver(ctx);
}
