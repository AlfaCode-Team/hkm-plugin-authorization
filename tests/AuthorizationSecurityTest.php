<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Authorization;

use AlfacodeTeam\PhpServicePlatform\Kernel\Exceptions\ServiceException;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\DatabasePort;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Authorization\Application\Services\AuthorizationService;
use Plugins\Authorization\Infrastructure\Persistence\DatabasePolicyAdapter;

/**
 * Regression cover for A-01 (domain-scoped grants applied globally) and A-02
 * (a partial savePolicy left authorization empty — a fail-closed lockout).
 */
#[CoversClass(AuthorizationService::class)]
#[CoversClass(DatabasePolicyAdapter::class)]
final class AuthorizationSecurityTest extends TestCase
{
    // ── A-01 ────────────────────────────────────────────────────────────────

    /**
     * A service on the domain-less model with a WRITABLE, in-memory store.
     *
     * It used to point the enforcer at an empty CSV, which made it file-backed
     * — and Casbin's FileAdapter cannot accept a per-rule write: InternalEnforcer
     * calls addPolicy inside `catch (NotImplementedException) {}`, so the rule
     * lands in the in-memory model, is silently never persisted, and the caller
     * is told `true`. AuthorizationService now refuses that write outright
     * (assertWritable), so a file fixture no longer exercises the un-scoped API
     * this test is about; it would only re-assert the refusal.
     *
     * The double below is what the test always meant: a store that actually
     * accepts writes, without needing a database.
     */
    private function serviceOnDomainlessModel(): AuthorizationService
    {
        $enforcer = new \Plugins\Authorization\Engine\Enforcer(
            __DIR__ . '/../config/rbac_model.conf',
            new InMemoryPolicyAdapter(),
        );

        return new AuthorizationService($enforcer);
    }

    protected function setUp(): void
    {
        @mkdir(__DIR__ . '/fixtures', 0775, true);
        file_put_contents(__DIR__ . '/fixtures/empty-policy.csv', '');
    }

    public function test_the_shipped_model_is_domain_less(): void
    {
        // Pinning the premise of A-01: g has two tokens, and the matcher never
        // mentions a domain — so any "domain-scoped" grant matches everywhere.
        $conf = (string) file_get_contents(__DIR__ . '/../config/rbac_model.conf');

        self::assertMatchesRegularExpression('/^g\s*=\s*_,\s*_\s*$/m', $conf);
        self::assertStringNotContainsString('r.dom', $conf);
    }

    public function test_a_domain_aware_model_is_available(): void
    {
        $conf = (string) file_get_contents(__DIR__ . '/../config/rbac_with_domains_model.conf');

        self::assertMatchesRegularExpression('/^g\s*=\s*_,\s*_,\s*_\s*$/m', $conf);
        self::assertStringContainsString('r.dom', $conf);
    }

    public function test_a_domain_scoped_grant_is_refused_on_a_domain_less_model(): void
    {
        // Silently granting GLOBALLY when the caller asked for one tenant is
        // cross-tenant privilege escalation; refusing is the only safe answer.
        $this->expectException(ServiceException::class);
        $this->expectExceptionMessage('authorization.domain.unsupported');

        $this->serviceOnDomainlessModel()->assignRole('alice', 'admin', 'tenant-a');
    }

    public function test_a_domain_less_grant_still_works(): void
    {
        // The un-scoped API is unaffected — it never claimed to isolate.
        // One instance: each call to the factory builds a fresh enforcer from
        // the same empty fixture, so a second one would not see the grant.
        $service = $this->serviceOnDomainlessModel();
        $service->assignRole('alice', 'admin');

        self::assertContains('admin', $service->rolesOf('alice'));
    }

    public function test_a_write_to_a_file_backed_store_is_refused(): void
    {
        // Casbin swallows FileAdapter's NotImplementedException, so without this
        // guard the grant would report success and vanish on the next request —
        // the worst possible outcome for an admin console.
        $service = new AuthorizationService(new \Plugins\Authorization\Engine\Enforcer(
            __DIR__ . '/../config/rbac_model.conf',
            __DIR__ . '/fixtures/empty-policy.csv',
        ));

        $this->expectException(ServiceException::class);
        $this->expectExceptionMessage('authorization.store.read_only');

        $service->grant('alice', 'users', 'edit');
    }

    public function test_a_file_backed_store_is_still_readable(): void
    {
        file_put_contents(__DIR__ . '/fixtures/empty-policy.csv', "p, admin, users, edit\ng, alice, admin\n");

        $service = new AuthorizationService(new \Plugins\Authorization\Engine\Enforcer(
            __DIR__ . '/../config/rbac_model.conf',
            __DIR__ . '/fixtures/empty-policy.csv',
        ));

        self::assertContains('admin', $service->rolesOf('alice'));
        self::assertSame(['users:edit'], $service->permissionsOf('alice'));
        self::assertTrue($service->allows('alice', 'users', 'edit'));
    }

    // ── A-03: the permission list is assembled from the right columns ───────

    public function test_permissions_are_read_from_the_right_columns_under_a_domain_model(): void
    {
        // `$rule[1] . ':' . $rule[2]` is object:action on a three-column policy
        // and domain:object on a four-column one — this used to return
        // "*:tenancy" where the permission is "tenancy:admin".
        // The POLICY domain is spelled out too, not `*`. enforce() honours
        // `p.dom == "*"`, but getImplicitPermissionsForUser() filters policies
        // by exact domain and skips a `*` row — so permissionsOf() under-reports
        // globally-scoped grants. Upstream Casbin behaviour, reporting only;
        // pinned here as it IS, not as one might wish.
        //
        // SCOPED, not global: the shipped matcher compares domains with
        // `r.dom == p.dom`, and a role assignment is resolved by the role
        // manager, which only gains wildcard domains when the matcher contains
        // the literal `keyMatch(r_dom, p_dom)` (CoreEnforcer::initRmMap). So
        // `g, alice, platform-admin, *` would match the domain spelled "*" and
        // nothing else — a separate limitation, not what this test is about.
        file_put_contents(__DIR__ . '/fixtures/domain-policy.csv',
            "p, platform-admin, tenant-a, tenancy, admin\ng, alice, platform-admin, tenant-a\n");

        $service = new AuthorizationService(new \Plugins\Authorization\Engine\Enforcer(
            __DIR__ . '/../config/rbac_with_domains_model.conf',
            __DIR__ . '/fixtures/domain-policy.csv',
        ));

        self::assertSame(['tenancy:admin'], $service->permissionsOf('alice', 'tenant-a'));
    }

    public function test_the_domain_aware_model_is_recognised_as_domain_aware(): void
    {
        // modelSupportsDomains() read `$model->model[...]`, an undefined property
        // (Model keeps assertions in a protected $items behind ArrayAccess), so
        // it answered false for EVERY model and refused every scoped call.
        $service = new AuthorizationService(new \Plugins\Authorization\Engine\Enforcer(
            __DIR__ . '/../config/rbac_with_domains_model.conf',
            new InMemoryPolicyAdapter(),
        ));

        // No exception = the domain guard accepted the model.
        self::assertSame([], $service->rolesOf('nobody', 'tenant-a'));
    }

    // ── A-02 ────────────────────────────────────────────────────────────────

    public function test_a_failed_save_rolls_back_rather_than_emptying_the_policy(): void
    {
        $db = new class implements DatabasePort {
            public array $calls = [];
            public bool $inTx = false;

            public function query(string $sql, array $p = []): array { return []; }
            public function queryOne(string $sql, array $p = []): ?array { return null; }
            public function execute(string $sql, array $p = []): int
            {
                $this->calls[] = str_starts_with($sql, 'DELETE') ? 'delete' : 'insert';
                if (str_starts_with($sql, 'INSERT')) {
                    throw new \PDOException('write failed mid-way');
                }
                return 1;
            }
            public function upsert(string $t, array $v, array $c, ?array $u = null): int { return 1; }
            public function lastInsertId(?string $s = null): string { return '1'; }
            public function beginTransaction(): void { $this->inTx = true; $this->calls[] = 'begin'; }
            public function commit(): void { $this->inTx = false; $this->calls[] = 'commit'; }
            public function rollback(): void { $this->inTx = false; $this->calls[] = 'rollback'; }
            public function inTransaction(): bool { return $this->inTx; }
        };

        $model = new \Plugins\Authorization\Engine\Model\Model();
        $model->loadModel(__DIR__ . '/../config/rbac_model.conf');
        $model->addPolicy('p', 'p', ['alice', 'reports', 'read']);

        try {
            (new DatabasePolicyAdapter($db))->savePolicy($model);
            self::fail('expected the write failure to propagate');
        } catch (\Throwable) {
            // expected
        }

        // An empty policy table denies EVERYTHING — including to the admins who
        // would have to repair it. The delete must not survive on its own.
        self::assertContains('begin', $db->calls);
        self::assertContains('rollback', $db->calls);
        self::assertNotContains('commit', $db->calls);
    }
}

/**
 * A policy store that lives in an array — writable, unlike Casbin's FileAdapter,
 * and with no database behind it. Used where a test needs the un-scoped write
 * API to actually work.
 */
final class InMemoryPolicyAdapter implements \Plugins\Authorization\Engine\Interfaces\Persist\Adapter
{
    /** @var list<array{0:string,1:string,2:list<string>}> */
    private array $rules = [];

    public function loadPolicy(\Plugins\Authorization\Engine\Model\Model $model): void
    {
        foreach ($this->rules as [$sec, $ptype, $rule]) {
            $model->addPolicy($sec, $ptype, $rule);
        }
    }

    public function savePolicy(\Plugins\Authorization\Engine\Model\Model $model): void
    {
        $this->rules = [];
        foreach (['p', 'g'] as $sec) {
            foreach ($model[$sec] ?? [] as $ptype => $assertion) {
                foreach ($assertion->policy as $rule) {
                    $this->rules[] = [$sec, $ptype, $rule];
                }
            }
        }
    }

    public function addPolicy(string $sec, string $ptype, array $rule): void
    {
        $this->rules[] = [$sec, $ptype, $rule];
    }

    public function removePolicy(string $sec, string $ptype, array $rule): void
    {
        $this->rules = array_values(array_filter(
            $this->rules,
            static fn (array $r): bool => !($r[0] === $sec && $r[1] === $ptype && $r[2] === $rule),
        ));
    }

    public function removeFilteredPolicy(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues): void
    {
        $this->rules = array_values(array_filter($this->rules, static function (array $r) use ($sec, $ptype, $fieldIndex, $fieldValues): bool {
            if ($r[0] !== $sec || $r[1] !== $ptype) {
                return true;
            }
            foreach ($fieldValues as $offset => $value) {
                if ($value !== '' && ($r[2][$fieldIndex + $offset] ?? null) !== $value) {
                    return true;
                }
            }
            return false;
        }));
    }
}
