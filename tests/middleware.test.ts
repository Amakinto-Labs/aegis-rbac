import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { defineRoles } from "../src/define";
import { createRBACMiddleware } from "../src/middleware/hono";

const config = defineRoles({
	roles: {
		owner: { permissions: ["*"] },
		admin: { permissions: ["workspace:update", "members:invite", "brands:*"] },
		viewer: { permissions: ["workspace:read", "brands:read"] },
	},
	hierarchy: ["owner", "admin", "viewer"],
	superAdmin: "owner",
});

function createApp(role: string | undefined) {
	const app = new Hono();

	app.use("*", async (c, next) => {
		if (role) {
			c.set("workspaceRole", role);
		}
		await next();
	});

	const { requirePermission, requireRole } = createRBACMiddleware({
		config,
		getRole: (c) => (c as any).get("workspaceRole"),
	});

	app.get("/public", (c) => c.json({ ok: true }));
	app.get("/brands", requirePermission("brands:read"), (c) => c.json({ ok: true }));
	app.post("/brands", requirePermission("brands:write"), (c) => c.json({ ok: true }));
	app.put("/workspace", requirePermission("workspace:update"), (c) => c.json({ ok: true }));
	app.delete("/workspace", requireRole("owner"), (c) => c.json({ ok: true }));
	app.post("/members", requirePermission("members:invite"), (c) => c.json({ ok: true }));
	app.get("/reports", requirePermission("brands:read", "analytics:read"), (c) =>
		c.json({ ok: true }),
	);
	// Role-gated route that does NOT list owner explicitly
	app.post("/settings", requireRole("admin"), (c) => c.json({ ok: true }));
	// Route that reads ability from context
	app.get("/conditional", requirePermission("brands:read"), (c) => {
		const ability = c.get("ability");
		return c.json({ hasAbility: !!ability });
	});

	return app;
}

describe("requirePermission middleware", () => {
	test("allows owner to access everything", async () => {
		const app = createApp("owner");
		expect((await app.request("/brands")).status).toBe(200);
		expect((await app.request("/brands", { method: "POST" })).status).toBe(200);
		expect((await app.request("/workspace", { method: "PUT" })).status).toBe(200);
		expect((await app.request("/members", { method: "POST" })).status).toBe(200);
	});

	test("allows admin permissions", async () => {
		const app = createApp("admin");
		expect((await app.request("/brands")).status).toBe(200);
		expect((await app.request("/brands", { method: "POST" })).status).toBe(200);
		expect((await app.request("/workspace", { method: "PUT" })).status).toBe(200);
		expect((await app.request("/members", { method: "POST" })).status).toBe(200);
	});

	test("restricts viewer to read-only", async () => {
		const app = createApp("viewer");
		expect((await app.request("/brands")).status).toBe(200);
		expect((await app.request("/brands", { method: "POST" })).status).toBe(403);
		expect((await app.request("/workspace", { method: "PUT" })).status).toBe(403);
		expect((await app.request("/members", { method: "POST" })).status).toBe(403);
	});

	test("returns 401 when no role is set", async () => {
		const app = createApp(undefined);
		expect((await app.request("/brands")).status).toBe(401);
	});

	test("does not affect unprotected routes", async () => {
		const app = createApp(undefined);
		expect((await app.request("/public")).status).toBe(200);
	});

	test("multi-permission check requires ALL permissions", async () => {
		const app = createApp("viewer");
		expect((await app.request("/reports")).status).toBe(403);
	});

	test("multi-permission check passes when all permissions are met", async () => {
		const app = createApp("owner");
		expect((await app.request("/reports")).status).toBe(200);
	});
});

describe("requireRole middleware", () => {
	test("allows matching role", async () => {
		const app = createApp("owner");
		expect((await app.request("/workspace", { method: "DELETE" })).status).toBe(200);
	});

	test("rejects non-matching role", async () => {
		const app = createApp("viewer");
		expect((await app.request("/workspace", { method: "DELETE" })).status).toBe(403);
	});

	test("super admin bypasses role check even when not in allowedRoles", async () => {
		const app = createApp("owner");
		expect((await app.request("/settings", { method: "POST" })).status).toBe(200);
	});

	test("higher role in hierarchy passes requireRole for lower role", async () => {
		// owner is above admin in hierarchy, should pass requireRole("admin")
		// This works via hierarchy, not just superAdmin
		const noSuperConfig = defineRoles({
			roles: {
				owner: { permissions: ["*"] },
				admin: { permissions: ["workspace:update"] },
				viewer: { permissions: ["workspace:read"] },
			},
			hierarchy: ["owner", "admin", "viewer"],
			// No superAdmin set!
		});
		const app = new Hono();
		app.use("*", async (c, next) => {
			c.set("workspaceRole", "owner");
			await next();
		});
		const { requireRole } = createRBACMiddleware({
			config: noSuperConfig,
			getRole: (c) => (c as any).get("workspaceRole"),
		});
		app.post("/admin-only", requireRole("admin"), (c) => c.json({ ok: true }));
		expect((await app.request("/admin-only", { method: "POST" })).status).toBe(200);
	});

	test("lower role in hierarchy cannot access higher role gate", async () => {
		const app = createApp("viewer");
		// viewer is below admin in hierarchy
		expect((await app.request("/settings", { method: "POST" })).status).toBe(403);
	});

	test("non-super-admin cannot bypass role check", async () => {
		const app = createApp("viewer");
		expect((await app.request("/settings", { method: "POST" })).status).toBe(403);
	});

	test("returns 401 when no role is set", async () => {
		const app = createApp(undefined);
		expect((await app.request("/workspace", { method: "DELETE" })).status).toBe(401);
	});
});

describe("ability on context", () => {
	test("sets ability on context after requirePermission", async () => {
		const app = createApp("admin");
		const res = await app.request("/conditional");
		const body = await res.json();
		expect(body).toEqual({ hasAbility: true });
	});
});

describe("custom error handlers", () => {
	test("uses custom onForbidden handler", async () => {
		const app = new Hono();
		app.use("*", async (c, next) => {
			c.set("workspaceRole", "viewer");
			await next();
		});
		const { requirePermission } = createRBACMiddleware({
			config,
			getRole: (c) => (c as any).get("workspaceRole"),
			onForbidden: (c) => c.json({ message: "nope", code: "FORBIDDEN" }, 403),
		});
		app.post("/brands", requirePermission("brands:write"), (c) => c.json({ ok: true }));
		const res = await app.request("/brands", { method: "POST" });
		expect(res.status).toBe(403);
		const body = await res.json();
		expect(body).toEqual({ message: "nope", code: "FORBIDDEN" });
	});

	test("uses custom onUnauthorized handler", async () => {
		const app = new Hono();
		const { requirePermission } = createRBACMiddleware({
			config,
			getRole: () => undefined,
			onUnauthorized: (c) => c.json({ message: "login required" }, 401),
		});
		app.get("/brands", requirePermission("brands:read"), (c) => c.json({ ok: true }));
		const res = await app.request("/brands");
		expect(res.status).toBe(401);
		const body = await res.json();
		expect(body).toEqual({ message: "login required" });
	});
});

describe("empty requirePermission", () => {
	test("throws at setup time when called with no permissions", () => {
		expect(() => {
			createRBACMiddleware({
				config,
				getRole: () => "admin",
			}).requirePermission();
		}).toThrow("requires at least one permission");
	});
});

describe("middleware with getContext", () => {
	test("resolves conditional permissions via getContext", async () => {
		const conditionalConfig = defineRoles({
			roles: {
				editor: {
					permissions: ["posts:read"],
					when: [{ permission: "posts:update", conditions: { authorId: "{{userId}}" } }],
				},
			},
		});
		const app = new Hono();
		app.use("*", async (c, next) => {
			c.set("workspaceRole", "editor");
			c.set("userId", "user-123");
			await next();
		});
		const { requirePermission } = createRBACMiddleware({
			config: conditionalConfig,
			getRole: (c) => (c as any).get("workspaceRole"),
			getContext: (c) => ({ userId: (c as any).get("userId") }),
		});
		app.put("/posts", requirePermission("posts:update"), (c) => c.json({ ok: true }));
		const res = await app.request("/posts", { method: "PUT" });
		expect(res.status).toBe(200);
	});
});

describe("error response format", () => {
	test("returns JSON error on 403", async () => {
		const app = createApp("viewer");
		const res = await app.request("/workspace", { method: "PUT" });
		const body = await res.json();
		expect(body).toEqual({ data: null, error: "Forbidden" });
	});

	test("returns JSON error on 401", async () => {
		const app = createApp(undefined);
		const res = await app.request("/brands");
		const body = await res.json();
		expect(body).toEqual({ data: null, error: "Unauthorized" });
	});
});
