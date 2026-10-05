<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Authorization\Support;

/**
 * The role policies the Subject tests read. Written at run time, like every
 * other file under tests/fixtures/ (which is gitignored), so a checkout needs
 * nothing but the test sources.
 */
final class RolePolicyFixtures
{
    public static function write(): void
    {
        $dir = __DIR__ . '/../fixtures';
        @mkdir($dir, 0775, true);

        file_put_contents($dir . '/role-policy.csv', <<<'CSV'
            p, owner, *, *
            p, editor, posts, edit
            p, finance, payments, read
            p, finance, payments, refund
            g, admin, editor
            g, alice, owner

            CSV);

        file_put_contents($dir . '/role-domain-policy.csv', "p, editor, tenant-a, posts, edit\n");
    }
}
