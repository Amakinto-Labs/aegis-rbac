import {
	type AbilityTuple,
	type MongoAbility,
	type RawRuleOf,
	createMongoAbility,
} from "@casl/ability";
import { parsePermission } from "./permission";
import type { AbilityContext, ConditionalPermission, FieldPermission, RBACConfig } from "./types";

/** Cache: WeakMap<config, Map<cacheKey, ability>> */
const abilityCache = new WeakMap<RBACConfig, Map<string, MongoAbility<AbilityTuple>>>();

function makeCacheKey(role: string, context?: AbilityContext): string {
	if (!context) return role;
	return `${role}:${JSON.stringify(context)}`;
}

/**
 * Resolve a single {{placeholder}} value against the provided context.
 * Returns the original value if it's not a placeholder string.
 */
function resolvePlaceholder(value: unknown, context: AbilityContext): unknown {
	if (typeof value !== "string") return value;
	const match = value.match(/^\{\{(\w+)\}\}$/);
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
function resolveConditions(
	conditions: Record<string, unknown>,
	context: AbilityContext,
): Record<string, unknown> {
	const resolved: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(conditions)) {
		if (value !== null && typeof value === "object" && !Array.isArray(value)) {
			resolved[key] = resolveConditions(value as Record<string, unknown>, context);
		} else {
			resolved[key] = resolvePlaceholder(value, context);
		}
	}
	return resolved;
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
	const key = makeCacheKey(role, context);

	// Check cache
	let roleCache = abilityCache.get(config);
	if (roleCache) {
		const cached = roleCache.get(key);
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

		// Conditional permissions — resolve {{placeholders}} if context provided
		const conditionals = collectConditionalPermissions(config, role);
		for (const cp of conditionals) {
			const { action, subject } = parsePermission(cp.permission);
			const conditions = context ? resolveConditions(cp.conditions, context) : cp.conditions;
			rules.push({ action, subject, conditions });
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
	roleCache.set(key, ability);

	return ability;
}
