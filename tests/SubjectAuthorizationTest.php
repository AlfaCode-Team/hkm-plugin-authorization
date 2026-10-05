<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Authorization;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Authorization\API\Subject;
use Plugins\Authorization\Application\Services\SubjectAuthorizationService;
use Plugins\Authorization\Engine\Enforcer;

/**
 * The policy is checked for the roles a project resolved, never for the
 * store's own user assignments. Real engine, real model files, CSV policy.
 */
#[CoversClass(SubjectAuthorizationService::class)]
#[CoversClass(Subject::class)]
final class SubjectAuthorizationTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        require_once __DIR__ . '/Support/RolePolicyFixtures.php';
        Support\RolePolicyFixtures::write();
    }

    private static function service(string $model = 'rbac_model.conf', string $policy = 'role-policy.csv'): SubjectAuthorizationService
    {
        return new SubjectAuthorizationService(new Enforcer(
            __DIR__ . '/../config/' . $model,
            __DIR__ . '/fixtures/' . $policy,
        ));
    }

    public function test_a_role_is_allowed_what_its_rows_grant_and_nothing_else(): void
    {
        $finance = new Subject('u-1', ['finance']);

        self::assertTrue(self::service()->allows($finance, 'payments', 'refund'));
        self::assertFalse(self::service()->allows($finance, 'posts', 'edit'));
    }

    public function test_any_one_role_is_enough(): void
    {
        self::assertTrue(self::service()->allows(new Subject('u-1', ['finance', 'editor']), 'posts', 'edit'));
    }

    public function test_a_wildcard_role_is_allowed_anything(): void
    {
        self::assertTrue(self::service()->allows(new Subject('u-1', ['owner']), 'reports', 'erase'));
    }

    public function test_inheritance_between_roles_still_applies(): void
    {
        // `g, admin, editor` — a ROLE-to-role row, which the policy still owns.
        self::assertTrue(self::service()->allows(new Subject('u-1', ['admin']), 'posts', 'edit'));
    }

    public function test_the_stores_own_user_assignments_are_never_consulted(): void
    {
        // `g, alice, owner` is in the policy. The resolver said alice holds
        // nothing here, and the resolver is the authority.
        self::assertFalse(self::service()->allows(new Subject('alice', []), 'posts', 'edit'));
        self::assertFalse(self::service()->allows(new Subject('alice', ['nobody']), 'posts', 'edit'));
    }

    public function test_filter_expands_wildcards_and_keeps_the_callers_order(): void
    {
        $asked = ['posts:edit', 'payments:refund', 'not-a-permission', 'posts:edit', ':edit', 'posts:'];

        self::assertSame(['posts:edit', 'payments:refund'], self::service()->filter(new Subject('u-1', ['owner']), $asked));
        self::assertSame(['payments:refund'], self::service()->filter(new Subject('u-1', ['finance']), $asked));
        self::assertSame([], self::service()->filter(new Subject('u-1', []), $asked));
    }

    public function test_a_permission_splits_at_its_last_colon(): void
    {
        file_put_contents(__DIR__ . '/fixtures/colon-policy.csv', "p, auditor, reports:monthly, read\n");

        try {
            $held = self::service(policy: 'colon-policy.csv')->filter(new Subject('u-1', ['auditor']), ['reports:monthly:read']);
        } finally {
            @unlink(__DIR__ . '/fixtures/colon-policy.csv');
        }

        self::assertSame(['reports:monthly:read'], $held);
    }

    public function test_under_a_domain_model_the_subjects_domain_is_matched(): void
    {
        $service = self::service('rbac_with_domains_model.conf', 'role-domain-policy.csv');

        self::assertTrue($service->allows(new Subject('u-1', ['editor'], 'tenant-a'), 'posts', 'edit'));
        self::assertFalse($service->allows(new Subject('u-1', ['editor'], 'tenant-b'), 'posts', 'edit'));
    }

    public function test_under_a_domain_model_no_domain_is_refused_rather_than_guessed(): void
    {
        $service = self::service('rbac_with_domains_model.conf', 'role-domain-policy.csv');

        self::assertFalse($service->allows(new Subject('u-1', ['editor']), 'posts', 'edit'));
        self::assertFalse($service->allows(new Subject('u-1', ['editor'], ''), 'posts', 'edit'));
    }

    public function test_a_subject_cleans_its_role_list(): void
    {
        $subject = new Subject('u-1', [' editor ', 'editor', '', 7, null, 'finance']);

        self::assertSame(['editor', 'finance'], $subject->roles);
        self::assertTrue($subject->hasRole('finance'));
        self::assertFalse((new Subject('u-1', []))->hasRole('finance'));
        self::assertTrue((new Subject('u-1', ['', ' ']))->isRoleless());
    }
}
