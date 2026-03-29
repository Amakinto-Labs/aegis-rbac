import type { AbilityTuple, MongoAbility } from "@casl/ability";

/** A permission string in "resource:action" format, or "*" for full access */
export type Permission = string;

/** Condition for a conditional permission — matched against the resource instance */
export type PermissionCondition = Record<string, unknown>;

/** A conditional permission: grants access only when the resource matches the condition */
export interface ConditionalPermission {
	/** Permission in "resource:action" format */
	permission: Permission;
	/** Condition object matched against the resource. Supports MongoDB-style queries via CASL. */
	conditions: PermissionCondition;
}

/** A field-level permission: grants access to specific fields only */
export interface FieldPermission {
	/** Permission in "resource:action" format */
	permission: Permission;
	/** Fields the role can access on this resource */
	fields: string[];
}

/** Configuration for a single role */
export interface RoleConfig {
	/** Permissions granted to this role in "resource:action" format */
	permissions: Permission[];
	/** Permissions explicitly denied, even if inherited or granted by wildcard.
	 *  Deny rules do NOT inherit through hierarchy — they only apply to this role. */
	deny?: Permission[];
	/** Conditional permissions — access only when resource matches conditions */
	when?: ConditionalPermission[];
	/** Field-level permissions — restrict which fields are accessible */
	fields?: FieldPermission[];
}

/** Full RBAC configuration for a project */
export interface RBACConfig<TRole extends string = string> {
	/** Role definitions mapping role names to their permissions */
	roles: Record<TRole, RoleConfig>;
	/**
	 * Optional role hierarchy (highest to lowest).
	 * Roles inherit all permissions from roles below them.
	 * Must include all defined roles when provided.
	 */
	hierarchy?: TRole[];
	/** Optional super admin role that bypasses all permission checks */
	superAdmin?: TRole;
}

/** Parsed permission split into resource and action */
export interface ParsedPermission {
	action: string;
	subject: string;
}

/** CASL ability type used throughout the package */
export type AppAbility = MongoAbility<AbilityTuple>;

/** Context passed to data scope resolvers */
export interface ScopeContext<TRole extends string = string> {
	userId: string;
	tenantId?: string;
	role: TRole;
	[key: string]: unknown;
}

/** A data scope resolver function */
export type ScopeResolver<TScope = unknown, TRole extends string = string> = (
	ctx: ScopeContext<TRole>,
) => TScope | Promise<TScope>;

/** Data scope configuration mapping roles to their scope resolvers */
export type DataScopeConfig<TRole extends string = string, TScope = unknown> = Partial<
	Record<TRole, ScopeResolver<TScope, TRole>>
>;

/** Options for resolveScope */
export interface ResolveScopeOptions<TScope> {
	/** Default scope when no resolver matches. If not provided and no resolver matches, resolveScope throws. */
	defaultScope?: TScope;
}

/** Context for resolving {{placeholder}} values in conditional permissions */
export interface AbilityContext {
	userId?: string;
	[key: string]: unknown;
}

/** Result from a framework-agnostic guard check */
export interface GuardResult {
	allowed: boolean;
	ability: AppAbility;
}

/** Override operations for a single role's permissions or deny rules */
export interface PermissionOverride {
	/** Permissions to add */
	add?: Permission[];
	/** Permissions to remove */
	remove?: Permission[];
}

/** Override operations for a single role's conditional permissions */
export interface ConditionalPermissionOverride {
	/** Conditional permissions to add */
	add?: ConditionalPermission[];
	/** Remove conditional permissions matching these permission strings */
	remove?: Permission[];
}

/** Override operations for a single role's field permissions */
export interface FieldPermissionOverride {
	/** Field permissions to add */
	add?: FieldPermission[];
	/** Remove field permissions matching these permission strings */
	remove?: Permission[];
}

/** Override definition for a single role */
export interface RoleOverride {
	/** Add or remove granted permissions */
	permissions?: PermissionOverride;
	/** Add or remove deny rules */
	deny?: PermissionOverride;
	/** Add or remove conditional permissions */
	when?: ConditionalPermissionOverride;
	/** Add or remove field-level permissions */
	fields?: FieldPermissionOverride;
}

/** Per-role overrides to apply on top of a base config */
export type RBACOverrides<TRole extends string = string> = Partial<Record<TRole, RoleOverride>>;
