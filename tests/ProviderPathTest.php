<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Authorization;

use AlfacodeTeam\PhpServicePlatform\Kernel\Support\Paths;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Authorization\Provider;

/**
 * A relative AUTHZ_POLICY_FILE / AUTHZ_MODEL_PATH means "in the project", not
 * "wherever this process happened to start".
 */
#[CoversClass(Provider::class)]
final class ProviderPathTest extends TestCase
{
    protected function tearDown(): void
    {
        Paths::setProject(null);
    }

    private static function resolve(string $path): string
    {
        return (new \ReflectionMethod(Provider::class, 'projectPath'))->invoke(null, $path);
    }

    public function test_a_relative_path_is_resolved_against_the_project_root(): void
    {
        Paths::setProject('/srv/app');

        self::assertSame('/srv/app/config/authz/policy.csv', self::resolve('config/authz/policy.csv'));
        self::assertSame('/srv/app/config/authz/policy.csv', self::resolve('  config/authz/policy.csv '));
    }

    public function test_an_absolute_path_is_left_alone(): void
    {
        Paths::setProject('/srv/app');

        self::assertSame('/etc/authz/policy.csv', self::resolve('/etc/authz/policy.csv'));
        self::assertSame('C:\\authz\\policy.csv', self::resolve('C:\\authz\\policy.csv'));
        self::assertSame('D:/authz/policy.csv', self::resolve('D:/authz/policy.csv'));
    }

    public function test_an_unset_path_stays_unset(): void
    {
        self::assertSame('', self::resolve(''));
        self::assertSame('', self::resolve('   '));
    }
}
