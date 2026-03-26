import { type AbilityTuple, type MongoAbility, createMongoAbility } from "@casl/ability";
import { parsePermission } from "./permission";
import type { RBACConfig } from "./types";

/** Cache: WeakMap<config, Map<role, ability>> — auto-GCs when config is dereferenced */
const abilityCache = new WeakMap<RBACConfig, Map<string, MongoAbility<AbilityTuple>>>();

/**
 * Collect all permissions for a role, including inherited permissions from hierarchy.
 */
export function collectPermissions<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
): string[] {
	const roleConfig = config.roles[role];
	if (!roleConfig) return [];

	const permissions = [...roleConfig.permissions];

	if (config.hierarchy) {
		const roleIndex = config.hierarchy.indexOf(role);
		if (roleIndex !== -1) {
			// Inherit permissions from all roles below in the hierarchy
			for (let i = roleIndex + 1; i < config.hierarchy.length; i++) {
				const lowerRole = config.hierarchy[i];
				const lowerConfig = config.roles[lowerRole];
				if (lowerConfig) {
					permissions.push(...lowerConfig.permissions);
				}
			}
		}
	}

	return permissions;
}

/**
 * Collect deny rules for a role. Deny rules are NOT inherited through hierarchy —
 * they only apply to the role that defines them.
 */
function collectDenyPermissions<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
): string[] {
	const roleConfig = config.roles[role];
	if (!roleConfig?.deny) return [];
	return [...roleConfig.deny];
}

/**
 * Build a CASL ability for a given role based on the RBAC config.
 * Results are cached per config+role — safe because configs are frozen.
 *
 * @example
 * ```ts
 * const ability = buildAbility(config, "admin");
 * ability.can("update", "workspace"); // true
 * ability.can("delete", "workspace"); // false
 * ```
 */
export function buildAbility<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
): MongoAbility<AbilityTuple> {
	// Check cache
	let roleCache = abilityCache.get(config);
	if (roleCache) {
		const cached = roleCache.get(role);
		if (cached) return cached;
	}

	let ability: MongoAbility<AbilityTuple>;

	// Super admin gets full access (deny rules do not apply)
	if (config.superAdmin && role === config.superAdmin) {
		ability = createMongoAbility([{ action: "manage", subject: "all" }]);
	} else {
		const permissions = collectPermissions(config, role);
		const allowRules = permissions.map((p) => {
			const { action, subject } = parsePermission(p);
			return { action, subject };
		});

		const denyPermissions = collectDenyPermissions(config, role);
		const denyRules = denyPermissions.map((p) => {
			const { action, subject } = parsePermission(p);
			return { action, subject, inverted: true };
		});

		ability = createMongoAbility([...allowRules, ...denyRules]);
	}

	// Store in cache
	if (!roleCache) {
		roleCache = new Map();
		abilityCache.set(config, roleCache);
	}
	roleCache.set(role, ability);

	return ability;
}
