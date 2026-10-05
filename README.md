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

A relative path (`AUTHZ_POLICY_FILE=config/authz/policy.csv`) is resolved
against the project root, not the process's working directory, so the same
`.env` works under the CLI, PHP-FPM and `php -S`. `AUTHZ_MODEL_PATH` is resolved
the same way.

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

### Roles from your application (`SubjectResolverContract`)

Most applications already know who holds which role — a membership table, a
`user_tenants.role` column. Copying that into `g` rows makes two stores that
must change together, and a role removed from one but not the other keeps
working. Since 1.3.0 the `can` filter can ask the application instead.

Bind a resolver from one of your modules (an essential one, so it is loaded on
every request that runs the filter):

```php
use Plugins\Authorization\API\Contracts\SubjectResolverContract;
use Plugins\Authorization\API\Subject;

$container->bind(SubjectResolverContract::class, fn ($c) => new class (/* … */) implements SubjectResolverContract {
    public function resolve(Request $request): ?Subject
    {
        // who, which roles they hold HERE (read live), and where "here" is
        return new Subject($userId, [$seatRole], $tenantId);
    }
});
```

The filter then checks the policy for those **roles**, so the policy only has to
say what a role may do:

```csv
p, owner,   *,        *
p, finance, payments, read
p, finance, payments, refund
g, admin,   owner
```

| The resolver returns | The filter |
|---|---|
| a `Subject` with roles | allows when any role is granted the route's `can:object,action` |
| a `Subject` with no roles | refuses — `DenialReason::NoRole` |
| `null` | does what it did before 1.3.0: judges `Identity->userId` against the store's `g` rows |
| throws | nothing is caught — the request fails as a server error, which still refuses it |

The resolved subject is attached to the request as `Subject::ATTRIBUTE`
(`authz.subject`), so a handler can ask more questions about the same person
without resolving them again. `SubjectAuthorizationContract` answers them:

```php
$authz->allows($subject, 'payments', 'refund');                    // one check
$authz->filter($subject, ['payments:refund', 'reports:download']); // which of these they hold
```

`filter()` asks the matcher about each permission, so wildcard rows expand
correctly (`p, owner, *, *` answers `payments:refund`), which a listing such as
`permissionsOf()` cannot do. Use it to decide which menu items and buttons to show.

The resolver also decides where the person is judged. Without one that is
`Identity->tenantId`, a hint the kernel does not vouch for. An application that
judges, for example, against the tenant that owns the hostname does that lookup
in its resolver. Under the domain-aware model the subject's `domain` is matched
against `p.dom`. Under the default model it is ignored, because the roles were
already looked up there.

### What a refusal looks like (`DenialResponderContract`)

The default refusal is a 401/403 with the standard error envelope, which suits
an API. A page someone opened in a browser usually needs something else: a page
that explains, or a redirect to the part of the application they can use. Bind
a `DenialResponderContract` to decide:

```php
public function respond(Request $request, Denial $denial): ?Response
{
    return match ($denial->reason) {
        DenialReason::NoRole    => Response::redirect('/elsewhere'),
        DenialReason::Forbidden => $this->noAccessPage($denial->permission()),
        default                 => null,   // the standard 401/403
    };
}
```

It controls only how the refusal looks: the request has already been refused,
and nothing it returns reaches the route's handler. Configuration faults (a
malformed `can:` declaration, or the module not loaded) are never passed to it.

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
