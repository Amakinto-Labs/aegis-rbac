import { describe, expect, it } from "bun:test";
import { defineRoles, can } from "../src";
import { createConfigCache } from "../src/cache";
import type { RBACOverrides } from "../src";

const base = defineRoles({
	roles: {
		admin: { permissions: ["*"] },
		editor: { permissions: ["posts:*", "comments:read"] },
		viewer: { permissions: ["posts:read", "comments:read"] },
	},
	hierarchy: ["admin", "editor", "viewer"],
	superAdmin: "admin",
});

describe("createConfigCache", () => {
	it("resolves and caches a config", async () => {
		let callCount = 0;
		const cache = createConfigCache({
			base,
			resolve: async () => {
				callCount++;
				return { viewer: { permissions: { add: ["analytics:read"] } } };
			},
		});

		const config1 = await cache.get("tenant-1");
		const config2 = await cache.get("tenant-1");

		expect(can(config1, "viewer", "analytics:read")).toBe(true);
		expect(config1).toBe(config2); // same reference = cache hit
		expect(callCount).toBe(1);
	});

	it("caches different tenants independently", async () => {
		const cache = createConfigCache<"admin" | "editor" | "viewer">({
			base,
			resolve: async (key) => {
				if (key === "tenant-a") {
					return { viewer: { permissions: { add: ["analytics:read"] } } };
				}
				return { viewer: { deny: { add: ["comments:read"] } } };
			},
		});

		const configA = await cache.get("tenant-a");
		const configB = await cache.get("tenant-b");

		expect(can(configA, "viewer", "analytics:read")).toBe(true);
		expect(can(configB, "viewer", "analytics:read")).toBe(false);
		expect(cache.size).toBe(2);
	});

	it("returns base clone when resolve returns empty overrides", async () => {
		const cache = createConfigCache({
			base,
			resolve: async () => ({}),
		});

		const config = await cache.get("tenant-1");
		expect(can(config, "viewer", "posts:read")).toBe(true);
		expect(config).not.toBe(base); // new object, not same reference
	});

	it("invalidates a single tenant", async () => {
		let callCount = 0;
		const cache = createConfigCache({
			base,
			resolve: async () => {
				callCount++;
				return {};
			},
		});

		await cache.get("tenant-1");
		expect(callCount).toBe(1);

		cache.invalidate("tenant-1");
		await cache.get("tenant-1");
		expect(callCount).toBe(2);
		expect(cache.size).toBe(1);
	});

	it("invalidateAll clears everything", async () => {
		const cache = createConfigCache({
			base,
			resolve: async () => ({}),
		});

		await cache.get("tenant-1");
		await cache.get("tenant-2");
		expect(cache.size).toBe(2);

		cache.invalidateAll();
		expect(cache.size).toBe(0);
	});

	describe("TTL", () => {
		it("expires entries after TTL", async () => {
			let callCount = 0;
			const cache = createConfigCache({
				base,
				resolve: async () => {
					callCount++;
					return {};
				},
				ttl: 0.1, // 100ms
			});

			await cache.get("tenant-1");
			expect(callCount).toBe(1);

			// Wait for TTL to expire
			await new Promise((r) => setTimeout(r, 150));

			await cache.get("tenant-1");
			expect(callCount).toBe(2);
		});

		it("serves from cache before TTL expires", async () => {
			let callCount = 0;
			const cache = createConfigCache({
				base,
				resolve: async () => {
					callCount++;
					return {};
				},
				ttl: 10, // 10 seconds — won't expire during test
			});

			await cache.get("tenant-1");
			await cache.get("tenant-1");
			await cache.get("tenant-1");
			expect(callCount).toBe(1);
		});

		it("no expiry when ttl is 0", async () => {
			let callCount = 0;
			const cache = createConfigCache({
				base,
				resolve: async () => {
					callCount++;
					return {};
				},
				ttl: 0,
			});

			await cache.get("tenant-1");
			await cache.get("tenant-1");
			expect(callCount).toBe(1);
		});
	});

	describe("concurrency", () => {
		it("deduplicates concurrent requests for the same key", async () => {
			let callCount = 0;
			const cache = createConfigCache({
				base,
				resolve: async () => {
					callCount++;
					await new Promise((r) => setTimeout(r, 50));
					return {};
				},
			});

			const [config1, config2, config3] = await Promise.all([
				cache.get("tenant-1"),
				cache.get("tenant-1"),
				cache.get("tenant-1"),
			]);

			expect(callCount).toBe(1);
			expect(config1).toBe(config2);
			expect(config2).toBe(config3);
		});
	});

	it("works with sync resolve function", async () => {
		const cache = createConfigCache({
			base,
			resolve: () => ({ viewer: { permissions: { add: ["analytics:read"] } } }),
		});

		const config = await cache.get("tenant-1");
		expect(can(config, "viewer", "analytics:read")).toBe(true);
	});
});
