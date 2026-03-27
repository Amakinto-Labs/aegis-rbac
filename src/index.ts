// Config
export { defineRoles } from "./define";
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
	ScopeContext,
	ScopeResolver,
	DataScopeConfig,
	ResolveScopeOptions,
	GuardResult,
} from "./types";
export type { DebugTrace, DebugResult, DebugRoleResult } from "./debug";
