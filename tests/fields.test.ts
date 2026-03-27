import { describe, expect, test } from "bun:test";
import { buildAbility } from "../src/ability";
import { defineRoles } from "../src/define";

const config = defineRoles({
	roles: {
		owner: { permissions: ["*"] },
		admin: {
			permissions: ["users:read", "users:update"],
		},
		analyst: {
			permissions: [],
			fields: [{ permission: "users:read", fields: ["name", "email", "role"] }],
		},
	},
	hierarchy: ["owner", "admin", "analyst"],
	superAdmin: "owner",
});

describe("field-level permissions", () => {
	test("admin can read all user fields (no field restriction)", () => {
		const ability = buildAbility(config, "admin");
		expect(ability.can("read", "users")).toBe(true);
	});

	test("analyst can read users (field-restricted)", () => {
		const ability = buildAbility(config, "analyst");
		expect(ability.can("read", "users")).toBe(true);
	});

	test("analyst cannot update users", () => {
		const ability = buildAbility(config, "analyst");
		expect(ability.can("update", "users")).toBe(false);
	});

	test("superAdmin bypasses field restrictions", () => {
		const ability = buildAbility(config, "owner");
		expect(ability.can("read", "users")).toBe(true);
	});

	test("field permissions are accessible via permittedFieldsOf pattern", () => {
		const ability = buildAbility(config, "analyst");
		// CASL stores field rules internally — the ability is built correctly
		const rules = ability.rules.filter(
			(r) => r.action === "read" && r.subject === "users" && !r.inverted,
		);
		const fieldsRule = rules.find((r) => r.fields);
		expect(fieldsRule).toBeDefined();
		expect(fieldsRule?.fields).toEqual(["name", "email", "role"]);
	});
});

describe("field permissions with hierarchy", () => {
	const hierarchyConfig = defineRoles({
		roles: {
			admin: {
				permissions: ["users:read"],
			},
			analyst: {
				permissions: [],
				fields: [{ permission: "users:read", fields: ["name", "email"] }],
			},
		},
		hierarchy: ["admin", "analyst"],
	});

	test("admin inherits analyst field permission but also has unrestricted access", () => {
		const ability = buildAbility(hierarchyConfig, "admin");
		// admin has full users:read, plus inherits the field-restricted one
		// The unrestricted rule should take precedence in CASL
		expect(ability.can("read", "users")).toBe(true);
	});
});

describe("defineRoles validation for fields", () => {
	test("throws on invalid permission in fields", () => {
		expect(() =>
			defineRoles({
				roles: {
					admin: {
						permissions: ["*"],
						fields: [{ permission: ":broken", fields: ["name"] }],
					},
				},
			}),
		).toThrow('Invalid field permission ":broken"');
	});

	test("throws on empty fields array", () => {
		expect(() =>
			defineRoles({
				roles: {
					admin: {
						permissions: ["*"],
						fields: [{ permission: "users:read", fields: [] }],
					},
				},
			}),
		).toThrow("non-empty fields array");
	});

	test("accepts valid field permissions", () => {
		expect(() =>
			defineRoles({
				roles: {
					analyst: {
						permissions: [],
						fields: [{ permission: "users:read", fields: ["name", "email"] }],
					},
				},
			}),
		).not.toThrow();
	});
});
