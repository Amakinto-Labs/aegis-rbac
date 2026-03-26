// Config
export { defineRoles } from "./define";
export { defineDataScope, resolveScope } from "./scope";

// Core
export { buildAbility } from "./ability";
export { can, authorize, getPermissions } from "./check";
export { parsePermission } from "./permission";
export { isRoleAtOrAbove } from "./hierarchy";
export { createGuard } from "./guard";

// Types
export type {
	Permission,
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
