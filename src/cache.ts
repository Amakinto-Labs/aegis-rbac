import type { RBACConfig, RBACOverrides } from "./types";
import { applyOverrides } from "./override";

/** Options for createConfigCache */
export interface ConfigCacheOptions<TRole extends string = string> {
	/** Base RBAC config (from defineRoles) */
	base: Readonly<RBACConfig<TRole>>;
	/** Async resolver that returns per-tenant overrides. Return empty object for no overrides. */
	resolve: (key: string) => RBACOverrides<TRole> | Promise<RBACOverrides<TRole>>;
	/** Cache TTL in seconds. 0 = no expiry (caller controls invalidation). Default: 0 */
	ttl?: number;
}

/** Cached RBAC config manager for multi-tenant applications */
export interface ConfigCache<TRole extends string = string> {
	/** Get or build the effective config for a tenant. Cached after first call. */
	get(key: string): Promise<Readonly<RBACConfig<TRole>>>;
	/** Invalidate a single tenant's cached config */
	invalidate(key: string): void;
	/** Invalidate all cached configs */
	invalidateAll(): void;
	/** Number of currently cached configs */
	readonly size: number;
}

interface CacheEntry<TRole extends string> {
	config: Readonly<RBACConfig<TRole>>;
	expiresAt: number;
}

/**
 * Create a config cache for multi-tenant RBAC.
 * Caches the result of `applyOverrides(base, resolve(key))` per tenant key.
 *
 * @example
 * ```ts
 * const cache = createConfigCache({
 *   base: rbacConfig,
 *   resolve: async (tenantId) => loadOverridesFromDB(tenantId),
 *   ttl: 300, // 5 minutes
 * });
 *
 * const config = await cache.get("tenant-123");
 * // Use config with can(), buildAbility(), middleware, etc.
 *
 * // When a tenant updates their permissions:
 * cache.invalidate("tenant-123");
 * ```
 */
export function createConfigCache<TRole extends string = string>(
	options: ConfigCacheOptions<TRole>,
): ConfigCache<TRole> {
	const { base, resolve, ttl = 0 } = options;
	const entries = new Map<string, CacheEntry<TRole>>();
	const pending = new Map<string, Promise<Readonly<RBACConfig<TRole>>>>();

	function isExpired(entry: CacheEntry<TRole>): boolean {
		return ttl > 0 && Date.now() > entry.expiresAt;
	}

	async function buildConfig(key: string): Promise<Readonly<RBACConfig<TRole>>> {
		const overrides = await resolve(key);
		const hasOverrides = Object.keys(overrides).length > 0;
		const config = hasOverrides ? applyOverrides(base, overrides) : applyOverrides(base, {});
		entries.set(key, {
			config,
			expiresAt: ttl > 0 ? Date.now() + ttl * 1000 : 0,
		});
		return config;
	}

	return {
		async get(key: string): Promise<Readonly<RBACConfig<TRole>>> {
			const cached = entries.get(key);
			if (cached && !isExpired(cached)) {
				return cached.config;
			}

			// Deduplicate concurrent requests for the same key
			const inflight = pending.get(key);
			if (inflight) return inflight;

			const promise = buildConfig(key).finally(() => pending.delete(key));
			pending.set(key, promise);
			return promise;
		},

		invalidate(key: string): void {
			entries.delete(key);
		},

		invalidateAll(): void {
			entries.clear();
		},

		get size(): number {
			return entries.size;
		},
	};
}
