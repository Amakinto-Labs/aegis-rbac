import {
	type AbilityTuple,
	type MongoAbility,
	type RawRuleOf,
	createMongoAbility,
} from "@casl/ability";
import { parsePermission } from "./permission";
import type { ConditionalPermission, FieldPermission, RBACConfig } from "./types";

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
 * Collect conditional permissions for a role, including inherited ones from hierarchy.
 */
function collectConditionalPermissions<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
): ConditionalPermission[] {
	const roleConfig = config.roles[role];
	if (!roleConfig) return [];

	const conditionals = [...(roleConfig.when ?? [])];

	if (config.hierarchy) {
		const roleIndex = config.hierarchy.indexOf(role);
		if (roleIndex !== -1) {
			for (let i = roleIndex + 1; i < config.hierarchy.length; i++) {
				const lowerRole = config.hierarchy[i];
				const lowerConfig = config.roles[lowerRole];
				if (lowerConfig?.when) {
					conditionals.push(...lowerConfig.when);
				}
			}
		}
	}

	return conditionals;
}

/**
 * Collect field-level permissions for a role, including inherited ones from hierarchy.
 */
function collectFieldPermissions<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
): FieldPermission[] {
	const roleConfig = config.roles[role];
	if (!roleConfig) return [];

	const fieldPerms = [...(roleConfig.fields ?? [])];

	if (config.hierarchy) {
		const roleIndex = config.hierarchy.indexOf(role);
		if (roleIndex !== -1) {
			for (let i = roleIndex + 1; i < config.hierarchy.length; i++) {
				const lowerRole = config.hierarchy[i];
				const lowerConfig = config.roles[lowerRole];
				if (lowerConfig?.fields) {
					fieldPerms.push(...lowerConfig.fields);
				}
			}
		}
	}

	return fieldPerms;
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
 *
 * // Conditional: check against a resource instance
 * ability.can("update", subject("posts", { authorId: "user-123" }));
 *
 * // Field-level: check accessible fields
 * ability.can("read", "users"); // true — but only for allowed fields
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
		const rules: RawRuleOf<MongoAbility<AbilityTuple>>[] = [];

		// Standard permissions
		const permissions = collectPermissions(config, role);
		for (const p of permissions) {
			const { action, subject } = parsePermission(p);
			rules.push({ action, subject });
		}

		// Conditional permissions
		const conditionals = collectConditionalPermissions(config, role);
		for (const cp of conditionals) {
			const { action, subject } = parsePermission(cp.permission);
			rules.push({ action, subject, conditions: cp.conditions });
		}

		// Field-level permissions
		const fieldPerms = collectFieldPermissions(config, role);
		for (const fp of fieldPerms) {
			const { action, subject } = parsePermission(fp.permission);
			rules.push({ action, subject, fields: fp.fields });
		}

		// Deny rules
		const denyPermissions = collectDenyPermissions(config, role);
		for (const p of denyPermissions) {
			const { action, subject } = parsePermission(p);
			rules.push({ action, subject, inverted: true });
		}

		ability = createMongoAbility(rules);
	}

	// Store in cache
	if (!roleCache) {
		roleCache = new Map();
		abilityCache.set(config, roleCache);
	}
	roleCache.set(role, ability);

	return ability;
}
