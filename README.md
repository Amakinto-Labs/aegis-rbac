# aegis

Config-driven RBAC engine built on [CASL](https://casl.js.org/). Define roles and permissions once, use everywhere.

## Why

Every SaaS project needs authorization, and every team ends up building it differently — scattered `if (role === "admin")` checks, provider-specific RBAC tied to Clerk/WorkOS/Better Auth, or hand-rolled middleware that's hard to test.

This package solves that by separating the **engine** (how permissions are checked) from the **config** (what roles and permissions exist). The engine is shared across all projects. Each project only provides a config file defining its roles.

**What it replaces:**
- Per-project role-checking middleware
- Auth-provider-specific RBAC (Clerk roles, WorkOS roles, etc.)
- Ad-hoc permission logic scattered across route handlers

**What it does not replace:**
- Your auth provider (this is not authentication — it's authorization)
- Your database (roles are stored in your DB, this package reads them)

## How it works

```
Auth provider → "who is this user?" → userId
Your DB       → "what role do they have?" → role
This package  → "what can that role do?" → allowed/denied
```

The auth adapter tells you **who**. Your database tells you their **role**. This package decides **what they can do**.

## Install

This is an internal package. Add it as a workspace dependency or link it directly:

```bash
# In your project's package.json, add:
"aegis": "file:../aegis"

# Then install
bun install
```

## Quick start

### 1. Define roles

```ts
import { defineRoles } from "aegis";

export const rbacConfig = defineRoles({
  roles: {
    owner: { permissions: ["*"] },
    admin: {
      permissions: [
        "workspace:update",
        "members:invite",
        "members:remove",
        "brands:*",
      ],
    },
    viewer: {
      permissions: ["workspace:read", "brands:read"],
    },
  },
  hierarchy: ["owner", "admin", "viewer"],
  superAdmin: "owner",
});
```

### 2. Check permissions

```ts
import { can, authorize, getPermissions } from "aegis";

can(rbacConfig, "admin", "members:invite"); // true
can(rbacConfig, "viewer", "members:invite"); // false

// Throws if denied
authorize(rbacConfig, "viewer", "members:invite");
// Error: Forbidden: role "viewer" cannot "invite" on "members"

// Introspect what a role can do
const summary = getPermissions(rbacConfig, "admin");
// { permissions: [...], conditionals: [...], fields: [...], denied: [...] }
```

`can()` and `authorize()` are conservative string-based helpers: they only succeed for unconditional grants. Conditional or field-scoped access needs a concrete resource instance checked through `buildAbility()`.

### 3. Hono middleware

```ts
import { createRBACMiddleware, type RBACEnv } from "aegis/middleware/hono";

const { requirePermission, requireRole } = createRBACMiddleware({
  config: rbacConfig,
  getRole: (c) => c.get("workspaceRole"),
  getContext: (c) => ({ userId: c.get("userId") }), // optional — for downstream ability checks
});

app.get("/brands", requirePermission("brands:read"), handler);
app.post("/brands", requirePermission("brands:write"), handler);
app.delete("/workspace", requireRole("owner"), handler);

// Multiple permissions (all must pass)
app.get("/reports", requirePermission("brands:read", "analytics:read"), handler);

// Type-safe access to the CASL ability in downstream handlers
const app = new Hono<RBACEnv>();
app.get("/brands", requirePermission("brands:read"), (c) => {
  const ability = c.get("ability"); // typed as AppAbility
  const canEdit = ability.can("write", "brands");
  // ...
});
```

`requirePermission()` is also conservative: it only admits unconditional permission strings. For conditional or field-scoped rules, load the resource in the handler and check `c.get("ability")` against the concrete subject instance.

### 4. Framework-agnostic guard

Use `createGuard` with Express, Fastify, Elysia, or any framework:

```ts
import { createGuard } from "aegis";

const guard = createGuard(rbacConfig);

const { allowed, ability } = guard.checkPermission("admin", "brands:write");
if (!allowed) throw new Error("Forbidden");

// Role checks respect hierarchy
guard.checkRole("owner", "admin"); // { allowed: true } — owner is above admin
```

## Permission format

```
"*"              → full access (manage all)
"resource:*"     → full access to resource
"resource:action" → specific action on resource
"resource"       → shorthand for resource:* (manage)
```

## Hierarchy

Roles inherit all permissions from roles below them. When hierarchy is provided, all defined roles must be included.

```ts
hierarchy: ["owner", "admin", "manager", "analyst"]
//          ↑ inherits from all below
//                  ↑ inherits from manager + analyst
//                           ↑ inherits from analyst
//                                       ↑ no inheritance
```

`requireRole` also respects hierarchy — `requireRole("admin")` allows `owner` through.

## Super admin

A role marked as `superAdmin` bypasses all permission and role checks:

```ts
defineRoles({
  roles: { ... },
  superAdmin: "owner", // owner can do everything
});
```

## Deny rules

Explicitly deny permissions, even if granted by wildcard or inheritance:

```ts
defineRoles({
  roles: {
    admin: {
      permissions: ["brands:*"],
      deny: ["brands:delete"], // admin can manage brands, but not delete
    },
  },
});
```

Deny rules are scoped to the role that defines them — they do not propagate up the hierarchy. Super admin ignores deny rules.

## Conditional permissions

Grant access only when the resource matches specific conditions (e.g., "edit own posts"):

```ts
defineRoles({
  roles: {
    editor: {
      permissions: ["posts:read"],
      when: [
        {
          permission: "posts:update",
          conditions: { authorId: "{{userId}}" },
        },
      ],
    },
  },
});
```

Pass a `context` to resolve `{{placeholder}}` values at runtime:

```ts
import { subject } from "@casl/ability";
import { buildAbility, can } from "aegis";

// Build ability with context — {{userId}} resolves to "user-123"
const ability = buildAbility(config, "editor", { userId: "user-123" });
ability.can("update", subject("posts", { authorId: "user-123" })); // true
ability.can("update", subject("posts", { authorId: "other-user" })); // false
```

`context` is used to build abilities for concrete subject checks. The string-based helpers (`can()`, `authorize()`, `checkPermission()`, `requirePermission()`) stay conservative and do not treat conditional rules as granted without a resource instance. Super admin still bypasses conditions.

## Field-level permissions

Restrict which fields a role can access on a resource:

```ts
defineRoles({
  roles: {
    admin: {
      permissions: ["users:read", "users:update"], // all fields
    },
    analyst: {
      permissions: [],
      fields: [
        { permission: "users:read", fields: ["name", "email", "role"] },
      ],
    },
  },
});
```

Field restrictions are **optional** — if you don't define `fields`, the permission grants access to all fields. Use CASL's `permittedFieldsOf()` to retrieve allowed fields in your application layer, and do not rely on string-only helpers to authorize field-scoped access.

## Custom error responses

```ts
createRBACMiddleware({
  config: rbacConfig,
  getRole: (c) => c.get("workspaceRole"),
  onUnauthorized: (c) => c.json({ message: "Login required" }, 401),
  onForbidden: (c) => c.json({ message: "Access denied" }, 403),
});
```

## Data scoping

For row-level filtering based on user relationships:

```ts
import { defineDataScope, resolveScope } from "aegis";

const scopes = defineDataScope({
  platform_admin: () => ({ type: "platform_admin" }),
  tenant_admin: (ctx) => ({ type: "tenant_admin", tenantId: ctx.tenantId }),
  staff: async (ctx) => ({
    type: "staff",
    groupIds: await getStaffGroups(ctx.userId),
  }),
});

// Optional: validate scope roles match your RBAC config
const scopes = defineDataScope(scopeConfig, { rbacConfig });

const scope = await resolveScope(scopes, {
  userId: "user-123",
  tenantId: "tenant-456",
  role: "staff",
});
// { type: "staff", groupIds: ["group-1", "group-2"] }
```

`resolveScope` throws if no resolver matches. Pass `{ defaultScope }` to opt into a fallback.

## Multi-tenant

For SaaS apps where each tenant can customize permissions:

```ts
import { defineRoles, applyOverrides, createConfigCache, can } from "aegis";
import { createRBACMiddleware } from "aegis/middleware/hono";

// 1. Define base roles (shared across all tenants)
const base = defineRoles({
  roles: {
    admin: { permissions: ["*"] },
    editor: { permissions: ["posts:*", "comments:*"] },
    viewer: { permissions: ["posts:read", "comments:read"] },
  },
  hierarchy: ["admin", "editor", "viewer"],
  superAdmin: "admin",
});

// 2. Cache per-tenant configs with automatic override resolution
const configs = createConfigCache({
  base,
  resolve: async (tenantId) => loadOverridesFromDB(tenantId),
  ttl: 300, // optional: refresh every 5 minutes
});

// 3. Wire into middleware — resolve tenant + role per request
app.use("/*", async (c, next) => {
  const tenantId = c.get("tenantId");
  const config = await configs.get(tenantId);
  const { requirePermission } = createRBACMiddleware({
    config,
    getRole: (c) => c.get("userRole"),
  });
  return requirePermission("posts:read")(c, next);
});

// 4. Invalidate when a tenant updates their permissions
app.put("/permissions", async (c) => {
  const tenantId = c.get("tenantId");
  await saveOverridesToDB(tenantId, body);
  configs.invalidate(tenantId);
});
```

`createConfigCache` handles caching and deduplication. Each tenant gets its own frozen config via `applyOverrides()`. The resolve function is only called on cache miss or TTL expiry.

## Debugging

Understand why a permission check passed or failed:

```ts
import { debugCan, debugRole } from "aegis";

const result = debugCan(config, "viewer", "brands:write");
// {
//   role: "viewer",
//   permission: "brands:write",
//   allowed: false,
//   traces: [{ allowed: false, reason: 'Role "viewer" does not have "brands:write" or a covering wildcard' }],
//   effectivePermissions: ["workspace:read", "brands:read"]
// }

const roleResult = debugRole(config, "viewer", "admin");
// { allowed: false, reason: 'Denied: "viewer" is below "admin" in hierarchy' }
```

## Validation

`defineRoles()` validates your config at startup:

- Permission format (`resource:action`, `resource:*`, `*`)
- Deny permission format (same rules)
- Conditional permissions must have non-empty conditions
- Field permissions must have non-empty fields array
- Hierarchy must include all defined roles (no partial hierarchies)
- No duplicate roles in hierarchy
- `superAdmin` must exist in `roles`
- At least one role required

`parsePermission()` also validates at runtime — malformed permission strings throw immediately.

## API

| Export | Description |
|--------|-------------|
| `defineRoles(config)` | Define and validate RBAC config |
| `can(config, role, permission)` | Check permission (returns boolean) |
| `authorize(config, role, permission)` | Assert permission (throws on deny) |
| `getPermissions(config, role)` | List effective permissions for a role |
| `buildAbility(config, role)` | Get cached CASL ability for advanced use |
| `parsePermission(permission)` | Parse permission string to action/subject |
| `isRoleAtOrAbove(config, userRole, requiredRole)` | Check role hierarchy position |
| `createGuard(config)` | Framework-agnostic guard (checkPermission, checkRole) |
| `applyOverrides(config, overrides)` | Apply per-tenant permission overrides to a base config |
| `createConfigCache(options)` | Cache per-tenant configs with TTL + invalidation |
| `defineDataScope(config, options?)` | Define data scope resolvers |
| `resolveScope(config, ctx, options?)` | Resolve scope for a user |
| `debugCan(config, role, permission)` | Debug why a permission check passed/failed |
| `debugRole(config, userRole, ...requiredRoles)` | Debug why a role check passed/failed |
| `createRBACMiddleware(options)` | Create Hono middleware |

## Examples

See [`examples/`](./examples) for configs covering:

- **3-role workspace** — owner/editor/viewer
- **4-role workspace** — owner/admin/manager/analyst
- **Hierarchical with scoping** — platform_admin/tenant_admin/staff/member with row-level filtering

## License

MIT
