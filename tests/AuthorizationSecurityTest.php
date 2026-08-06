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

    private function serviceOnDomainlessModel(): AuthorizationService
    {
        $enforcer = new \Plugins\Authorization\Engine\Enforcer(
            __DIR__ . '/../config/rbac_model.conf',
            __DIR__ . '/fixtures/empty-policy.csv',
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
