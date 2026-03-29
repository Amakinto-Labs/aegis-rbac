// Config
export { defineRoles } from "./define";
export { applyOverrides } from "./override";
export { defineDataScope, resolveScope } from "./scope";

// Core
export { buildAbility } from "./ability";
export { can, authorize, getPermissions } from "./check";
export { parsePermission } from "./permission";
export { isRoleAtOrAbove } from "./hierarchy";
export { createGuard } from "./guard";

// Debug
export { debugCan, debugRole } from "./debug";

// Types
export type {
	Permission,
	PermissionCondition,
	ConditionalPermission,
	FieldPermission,
	RoleConfig,
	RBACConfig,
	ParsedPermission,
	AppAbility,
	AbilityContext,
	ScopeContext,
	ScopeResolver,
	DataScopeConfig,
	ResolveScopeOptions,
	GuardResult,
	RoleOverride,
	RBACOverrides,
} from "./types";
export type { PermissionsSummary } from "./check";
export type { DebugTrace, DebugResult, DebugRoleResult } from "./debug";
