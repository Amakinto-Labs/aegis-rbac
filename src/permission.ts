import type { ParsedPermission } from "./types";
import { isValidPermission } from "./validate";

/**
 * Parse a permission string into action + subject.
 * Maps to CASL conventions: "*" → manage all, "resource:*" → manage resource.
 * Throws on malformed input.
 *
 * @example
 * ```ts
 * parsePermission("*")              // { action: "manage", subject: "all" }
 * parsePermission("brands:read")    // { action: "read", subject: "brands" }
 * parsePermission("brands:*")       // { action: "manage", subject: "brands" }
 * parsePermission("brands")         // { action: "manage", subject: "brands" }
 * ```
 */
export function parsePermission(permission: string): ParsedPermission {
	if (!isValidPermission(permission)) {
		throw new Error(
			`Invalid permission "${permission}". Use "resource:action", "resource:*", or "*"`,
		);
	}

	if (permission === "*") {
		return { action: "manage", subject: "all" };
	}

	const colonIndex = permission.indexOf(":");
	if (colonIndex === -1) {
		return { action: "manage", subject: permission };
	}

	const subject = permission.slice(0, colonIndex);
	const action = permission.slice(colonIndex + 1);

	if (action === "*") {
		return { action: "manage", subject };
	}

	return { action, subject };
}

/**
 * Check whether a granted action implies a required action via action levels.
 * Returns true if the granted action is at a higher level than the required action.
 */
function actionImplies(
	actionLevels: string[] | undefined,
	grantedAction: string,
	requiredAction: string,
): boolean {
	if (!actionLevels) return false;
	const grantedIndex = actionLevels.indexOf(grantedAction);
	const requiredIndex = actionLevels.indexOf(requiredAction);
	// Both must be known levels, and granted must be higher (higher index = higher level)
	return grantedIndex !== -1 && requiredIndex !== -1 && grantedIndex > requiredIndex;
}

/**
 * Check whether a granted permission covers a required permission.
 * Used by the string-based helpers which only reason about permission strings,
 * not resource instances.
 * When actionLevels are provided, a higher-level action implies all lower-level actions.
 */
export function permissionMatches(
	grantedPermission: string,
	requiredPermission: string,
	actionLevels?: string[],
): boolean {
	const granted = parsePermission(grantedPermission);
	const required = parsePermission(requiredPermission);

	if (granted.subject === "all") {
		return granted.action === "manage";
	}

	if (granted.subject !== required.subject) {
		return false;
	}

	return (
		granted.action === "manage" ||
		granted.action === required.action ||
		actionImplies(actionLevels, granted.action, required.action)
	);
}
