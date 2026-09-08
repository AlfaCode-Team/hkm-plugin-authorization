# hkm-plugin-authorization

> HKM Kernel plugin — provides **`authorization.policy`**.
> Part of the [HKM Kernel](https://github.com/AlfaCode-Team/hkm-kernel) Gated Demand Architecture framework.

[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
![PHP](https://img.shields.io/badge/PHP-8.4%2B-777bb4)

## Install

```bash
composer require alfacode-team/hkm-plugin-authorization
# or, from a project:
hkm plugins add authorization
```

## Capability

Provides `authorization.policy`. Requires: `database.management`.

## Configuration

| Key | Type | Required | Meaning |
|---|---|---|---|
| `AUTHZ_MODEL_PATH` | string | no | Casbin model file. Defaults to the bundled `config/rbac_model.conf`. |
| `AUTHZ_POLICY_TABLE` | string | no | Policy table name. Defaults to `casbin_rule`. |
| `AUTHZ_POLICY_FILE` | string | no | Read the policy from a Casbin **CSV** instead of the table. |

### Policy in the database (default)

Rules live in `casbin_rule` through `DatabasePort`, and can be changed at
runtime — an admin UI, `authz:seed`, or the contract's own `assignRole`/`grant`.
Run the bundled migration to create the table.

### Policy in a file (`AUTHZ_POLICY_FILE`)

Points the enforcer at a CSV, so roles and permissions live in version control
and ship with the release. The model is already a file; this makes the policy
one too.

**That store is read-only, and the plugin says so rather than pretending.**
Casbin's `FileAdapter` throws `NotImplementedException` from
`addPolicy`/`removePolicy`, and `InternalEnforcer` swallows it in an empty
`catch` — so a write reaches the in-memory model, is never persisted, and still
returns `true`. An admin console would report success and lose the change on the
next request. `assignRole`, `revokeRole`, `grant` and `revoke` therefore fail up
front with `authorization.store.read_only`. Reads are unaffected.

A path that does not resolve fails at bind time, rather than booting with an
empty policy that denies everything — which reads like an authorization bug
instead of a missing file.

### Known limits of the domain-aware model

Both measured, and worth knowing before adopting `rbac_with_domains_model.conf`:

- **A `g` row cannot say "every domain".** Role assignments are resolved by the
  role manager, which compares domains with `===` unless the matcher contains
  the literal `keyMatch(r_dom, p_dom)` — that string is what registers the
  domain matching function. With the shipped matcher (`r.dom == p.dom`),
  `g, alice, admin, *` matches the domain spelled `*` and nothing else. Use a
  matcher with `keyMatch` if a role has to be held globally.
- **`permissionsOf()` under-reports `*` policies.** `enforce()` honours
  `p.dom == "*"`, but `getImplicitPermissionsForUser()` filters by exact domain
  and skips such a row. That list is for display; `allows()` is the authority.

## Documentation

- [Kernel guides](https://github.com/AlfaCode-Team/hkm-kernel/tree/main/docs/guides) — the framework contracts this plugin builds on.

## License

MIT — see [LICENSE](LICENSE).
