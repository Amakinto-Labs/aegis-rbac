import type { RBACConfig, RBACOverrides, RoleConfig } from "./types";
import { validateConfig, deepFreeze } from "./validate";

/**
 * Apply runtime overrides to a base RBAC config.
 * Returns a new deeply frozen config — the base config is not modified.
 *
 * Use this for per-tenant permission customization: define base roles at startup,
 * then apply tenant-specific overrides at request time.
 *
 * Callers own the caching strategy — for hot paths, cache the result per tenant:
 *
 * @example
 * ```ts
 * const base = defineRoles({ ... });
 *
 * // Cache per tenant
 * const tenantConfigs = new Map<string, RBACConfig>();
 * function getConfig(tenantId: string) {
 *   if (!tenantConfigs.has(tenantId)) {
 *     const overrides = loadOverridesFromDB(tenantId);
 *     tenantConfigs.set(tenantId, applyOverrides(base, overrides));
 *   }
 *   return tenantConfigs.get(tenantId)!;
 * }
 * ```
 *
 * @example
 * ```ts
 * const effective = applyOverrides(base, {
 *   editor: {
 *     permissions: { add: ["reports:read"], remove: ["messaging:*"] },
 *     deny: { add: ["payments:*"] },
 *   },
 * });
 * ```
 */
export function applyOverrides<TRole extends string>(
	baseConfig: Readonly<RBACConfig<TRole>>,
	overrides: RBACOverrides<TRole>,
): Readonly<RBACConfig<TRole>> {
	// Validate override keys reference known roles
	for (const role of Object.keys(overrides) as TRole[]) {
		if (!(role in baseConfig.roles)) {
			throw new Error(`Override references unknown role "${role}"`);
		}
	}

	// Build new roles object
	const newRoles = {} as Record<TRole, RoleConfig>;

	for (const role of Object.keys(baseConfig.roles) as TRole[]) {
		const base = baseConfig.roles[role];
		const patch = overrides[role];

		if (!patch) {
			// Clone unchanged
			newRoles[role] = cloneRoleConfig(base);
			continue;
		}

		// Start from cloned base
		const merged = cloneRoleConfig(base);

		// Apply permission overrides
		if (patch.permissions) {
			if (patch.permissions.add) {
				merged.permissions.push(...patch.permissions.add);
			}
			if (patch.permissions.remove) {
				const removeSet = new Set(patch.permissions.remove);
				merged.permissions = merged.permissions.filter((p) => !removeSet.has(p));
			}
		}

		// Apply deny overrides
		if (patch.deny) {
			if (!merged.deny) merged.deny = [];
			if (patch.deny.add) {
				merged.deny.push(...patch.deny.add);
			}
			if (patch.deny.remove) {
				const removeSet = new Set(patch.deny.remove);
				merged.deny = merged.deny.filter((p) => !removeSet.has(p));
			}
		}

		// Apply conditional permission overrides
		if (patch.when) {
			if (!merged.when) merged.when = [];
			if (patch.when.add) {
				merged.when.push(...patch.when.add);
			}
			if (patch.when.remove) {
				const removeSet = new Set(patch.when.remove);
				merged.when = merged.when.filter((cp) => !removeSet.has(cp.permission));
			}
		}

		// Apply field permission overrides
		if (patch.fields) {
			if (!merged.fields) merged.fields = [];
			if (patch.fields.add) {
				merged.fields.push(...patch.fields.add);
			}
			if (patch.fields.remove) {
				const removeSet = new Set(patch.fields.remove);
				merged.fields = merged.fields.filter((fp) => !removeSet.has(fp.permission));
			}
		}

		newRoles[role] = merged;
	}

	// Construct new config
	const newConfig: RBACConfig<TRole> = {
		roles: newRoles,
		...(baseConfig.hierarchy && { hierarchy: [...baseConfig.hierarchy] }),
		...(baseConfig.superAdmin !== undefined && { superAdmin: baseConfig.superAdmin }),
	};

	// Validate the merged result
	validateConfig(newConfig);

	return deepFreeze(newConfig);
}

function cloneRoleConfig(config: RoleConfig): RoleConfig {
	return {
		permissions: [...config.permissions],
		...(config.deny && { deny: [...config.deny] }),
		...(config.when && { when: config.when.map((cp) => ({ ...cp, conditions: { ...cp.conditions } })) }),
		...(config.fields && { fields: config.fields.map((fp) => ({ ...fp, fields: [...fp.fields] })) }),
	};
}
