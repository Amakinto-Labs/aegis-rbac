import {
	type AbilityTuple,
	type MongoAbility,
	type RawRuleOf,
	createMongoAbility,
} from "@casl/ability";
import { parsePermission, permissionMatches } from "./permission";
import type { AbilityContext, ConditionalPermission, FieldPermission, RBACConfig } from "./types";

/** Cache: WeakMap<config, Map<cacheKey, ability>> */
const abilityCache = new WeakMap<RBACConfig, Map<string, MongoAbility<AbilityTuple>>>();

export function isKnownRole<TRole extends string>(
	config: RBACConfig<TRole>,
	role: string,
): role is TRole {
	return role in config.roles;
}

export function createEmptyAbility(): MongoAbility<AbilityTuple> {
	return createMongoAbility([]);
}

/**
 * Resolve a single {{placeholder}} value against the provided context.
 * Returns the original value if it's not a placeholder string.
 */
function resolvePlaceholder(value: unknown, context: AbilityContext): unknown {
	if (typeof value !== "string") return value;
	const match = value.match(/^\{\{([\w.:-]+)\}\}$/);
	if (!match) return value;
	const key = match[1];
	if (!(key in context)) {
		throw new Error(
			`Condition placeholder "{{${key}}}" not found in context. Available keys: ${Object.keys(context).join(", ")}`,
		);
	}
	return context[key];
}

/**
 * Deep-resolve all {{placeholder}} values in a conditions object.
 */
function resolveConditions(value: unknown, context: AbilityContext): unknown {
	if (Array.isArray(value)) {
		return value.map((entry) => resolveConditions(entry, context));
	}

	if (value !== null && typeof value === "object") {
		const resolved: Record<string, unknown> = {};
		for (const [key, nestedValue] of Object.entries(value)) {
			resolved[key] = resolveConditions(nestedValue, context);
		}
		return resolved;
	}

	return resolvePlaceholder(value, context);
}

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
export function collectConditionalPermissions<TRole extends string>(
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
export function collectFieldPermissions<TRole extends string>(
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
 *
 * Rationale: if deny rules inherited downward, a higher role's deny would
 * silently restrict lower roles that never intended to be denied. Each role
 * should only deny permissions it explicitly declares.
 */
function collectDenyPermissions<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
): string[] {
	const roleConfig = config.roles[role];
	if (!roleConfig?.deny) return [];
	return [...roleConfig.deny];
}

export interface PermissionAnalysis {
	allowed: boolean;
	isSuperAdmin: boolean;
	grantedBy?: string;
	deniedBy?: string;
	conditionalMatches: ConditionalPermission[];
	fieldMatches: FieldPermission[];
}

/**
 * Analyze a permission string without evaluating a concrete resource instance.
 * Conditional and field-scoped rules are surfaced separately so callers can
 * stay conservative at route/helper level.
 */
export function analyzePermission<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
	permission: string,
): PermissionAnalysis {
	if (!isKnownRole(config, role)) {
		return {
			allowed: false,
			isSuperAdmin: false,
			conditionalMatches: [],
			fieldMatches: [],
		};
	}

	if (config.superAdmin && role === config.superAdmin) {
		return {
			allowed: true,
			isSuperAdmin: true,
			grantedBy: "*",
			conditionalMatches: [],
			fieldMatches: [],
		};
	}

	const denyPermissions = collectDenyPermissions(config, role);
	const deniedBy = denyPermissions.find((denyPermission) =>
		permissionMatches(denyPermission, permission, config.actionLevels),
	);
	if (deniedBy) {
		return {
			allowed: false,
			isSuperAdmin: false,
			deniedBy,
			conditionalMatches: [],
			fieldMatches: [],
		};
	}

	const grantedPermissions = collectPermissions(config, role);
	const grantedBy = grantedPermissions.find((grantedPermission) =>
		permissionMatches(grantedPermission, permission, config.actionLevels),
	);
	if (grantedBy) {
		return {
			allowed: true,
			isSuperAdmin: false,
			grantedBy,
			conditionalMatches: [],
			fieldMatches: [],
		};
	}

	return {
		allowed: false,
		isSuperAdmin: false,
		conditionalMatches: collectConditionalPermissions(config, role).filter((conditional) =>
			permissionMatches(conditional.permission, permission, config.actionLevels),
		),
		fieldMatches: collectFieldPermissions(config, role).filter((fieldPermission) =>
			permissionMatches(fieldPermission.permission, permission, config.actionLevels),
		),
	};
}

/**
 * Build a CASL ability for a given role based on the RBAC config.
 * Results are cached per config+role+context — safe because configs are frozen.
 *
 * When `context` is provided, `{{placeholder}}` values in conditional permission
 * conditions are resolved against it (e.g., `{{userId}}` becomes `context.userId`).
 *
 * @example
 * ```ts
 * // Without context — plain permissions only
 * const ability = buildAbility(config, "admin");
 * ability.can("update", "workspace"); // true
 *
 * // With context — conditional permissions resolved
 * const ability = buildAbility(config, "editor", { userId: "user-123" });
 * ability.can("update", subject("posts", { authorId: "user-123" })); // true
 * ability.can("update", subject("posts", { authorId: "other" }));    // false
 * ```
 */
export function buildAbility<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
	context?: AbilityContext,
): MongoAbility<AbilityTuple> {
	if (!isKnownRole(config, role)) {
		throw new Error(`Unknown role "${role}". Valid roles: ${Object.keys(config.roles).join(", ")}`);
	}

	const shouldCache = context === undefined;
	const key = role;

	// Check cache
	let roleCache = abilityCache.get(config);
	if (shouldCache && roleCache) {
		const cached = roleCache.get(key);
		if (cached) return cached;
	}

	let ability: MongoAbility<AbilityTuple>;

	// Super admin gets full access (deny rules do not apply)
	if (config.superAdmin && role === config.superAdmin) {
		ability = createMongoAbility([{ action: "manage", subject: "all" }]);
	} else {
		const rules: RawRuleOf<MongoAbility<AbilityTuple>>[] = [];

		// Standard permissions (with action level expansion)
		const permissions = collectPermissions(config, role);
		for (const p of permissions) {
			const { action, subject } = parsePermission(p);
			rules.push({ action, subject });
			// Expand implied actions from actionLevels
			if (config.actionLevels && action !== "manage") {
				const levelIndex = config.actionLevels.indexOf(action);
				if (levelIndex > 0) {
					for (let i = 0; i < levelIndex; i++) {
						rules.push({ action: config.actionLevels[i], subject });
					}
				}
			}
		}

		// Conditional permissions — resolve {{placeholders}} against context.
		// When context is omitted, conditional rules are silently skipped.
		// This is intentional: callers like checkRole() need an ability for
		// downstream use but don't have context yet.
		const conditionals = collectConditionalPermissions(config, role);
		if (context) {
			for (const cp of conditionals) {
				const { action, subject } = parsePermission(cp.permission);
				const conditions = resolveConditions(cp.conditions, context) as Record<string, unknown>;
				rules.push({ action, subject, conditions });
			}
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
	if (shouldCache) {
		if (!roleCache) {
			roleCache = new Map();
			abilityCache.set(config, roleCache);
		}
		roleCache.set(key, ability);
	}

	return ability;
}
