<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Authorization;

require_once __DIR__ . '/Support/trans_or.php';

use AlfacodeTeam\PhpServicePlatform\Kernel\Container\CoreContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Container\ModuleContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Authorization\API\Contracts\AuthorizationServiceContract;
use Plugins\Authorization\API\Contracts\DenialResponderContract;
use Plugins\Authorization\API\Contracts\SubjectAuthorizationContract;
use Plugins\Authorization\API\Contracts\SubjectResolverContract;
use Plugins\Authorization\API\Denial;
use Plugins\Authorization\API\DenialReason;
use Plugins\Authorization\API\Subject;
use Plugins\Authorization\Application\Services\AuthorizationService;
use Plugins\Authorization\Application\Services\SubjectAuthorizationService;
use Plugins\Authorization\Engine\Enforcer;
use Plugins\Authorization\Infrastructure\Http\Stages\PolicyFilterStage;

/**
 * The `can` filter, run as RouteFilterStage runs it: a request carrying the
 * Identity, the request container and the parsed `filter_args`.
 *
 * The plugin's contracts are bound the way its Provider binds them (public,
 * in the plugin's scope); a "project" binds the resolver and responder from
 * its own scope, which is the cross-scope resolution the design depends on.
 */
#[CoversClass(PolicyFilterStage::class)]
#[CoversClass(Denial::class)]
final class PolicyFilterStageTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        require_once __DIR__ . '/Support/RolePolicyFixtures.php';
        Support\RolePolicyFixtures::write();
    }

    /** What reached the handler, if anything. */
    private ?Request $passed = null;

    /** Every denial a bound responder was shown. @var list<Denial> */
    private array $denials = [];

    private function container(?SubjectResolverContract $resolver = null, ?DenialResponderContract $responder = null): ModuleContainer
    {
        $c = new ModuleContainer(new CoreContainer());

        $c->setScope('authorization.policy');
        $enforcer = static fn (): Enforcer => new Enforcer(
            __DIR__ . '/../config/rbac_model.conf',
            __DIR__ . '/fixtures/role-policy.csv',
        );
        $c->bind(AuthorizationServiceContract::class, static fn () => new AuthorizationService($enforcer()));
        $c->bind(SubjectAuthorizationContract::class, static fn () => new SubjectAuthorizationService($enforcer()));

        $c->setScope('__project__');
        if ($resolver !== null) {
            $c->bind(SubjectResolverContract::class, static fn () => $resolver);
        }
        if ($responder !== null) {
            $c->bind(DenialResponderContract::class, static fn () => $responder);
        }

        return $c;
    }

    private function filter(ModuleContainer $container, ?Identity $identity, string $object = 'payments', string $action = 'refund'): Response
    {
        $request = Request::create('/payments/1/refund', 'POST')
            ->withContainer($container)
            ->withAttribute('filter_args', ['can' => [$object, $action]]);

        if ($identity !== null) {
            $request = $request->withIdentity($identity);
        }

        $this->passed = null;

        return (new PolicyFilterStage())->handle($request, function (Request $r): Response {
            $this->passed = $r;

            return Response::json(['ok' => true]);
        });
    }

    private static function resolving(?Subject $subject): SubjectResolverContract
    {
        return new class ($subject) implements SubjectResolverContract {
            public function __construct(private readonly ?Subject $subject)
            {
            }

            public function resolve(Request $request): ?Subject
            {
                return $this->subject;
            }
        };
    }

    private function responder(?Response $answer): DenialResponderContract
    {
        $denials = &$this->denials;

        return new class ($answer, $denials) implements DenialResponderContract {
            /** @param list<Denial> $denials */
            public function __construct(private readonly ?Response $answer, private array &$denials)
            {
            }

            public function respond(Request $request, Denial $denial): ?Response
            {
                $this->denials[] = $denial;

                return $this->answer;
            }
        };
    }

    // ── With a resolver ─────────────────────────────────────────────────────

    public function test_the_resolved_roles_decide_and_the_subject_reaches_the_handler(): void
    {
        $subject = new Subject('u-1', ['finance'], 'tenant-a');

        $response = $this->filter($this->container(self::resolving($subject)), Identity::asUser('u-1'));

        self::assertSame(200, $response->getStatusCode());
        self::assertSame($subject, $this->passed?->attribute(Subject::ATTRIBUTE));
    }

    public function test_a_role_without_the_permission_is_forbidden(): void
    {
        $response = $this->filter(
            $this->container(self::resolving(new Subject('u-1', ['editor'])), $this->responder(null)),
            Identity::asUser('u-1'),
        );

        self::assertSame(403, $response->getStatusCode());
        self::assertNull($this->passed);
        self::assertSame(DenialReason::Forbidden, $this->denials[0]->reason);
        self::assertSame('payments:refund', $this->denials[0]->permission());
    }

    public function test_no_role_here_is_its_own_reason(): void
    {
        $page = Response::html('<p>Not for you</p>', 403);

        $response = $this->filter(
            $this->container(self::resolving(new Subject('u-1', [])), $this->responder($page)),
            Identity::asUser('u-1'),
        );

        self::assertSame($page, $response);
        self::assertSame(DenialReason::NoRole, $this->denials[0]->reason);
        self::assertSame('u-1', $this->denials[0]->subject?->id);
    }

    public function test_the_stores_user_rows_do_not_rescue_a_subject(): void
    {
        // alice is `g, alice, owner` in the policy; the resolver says otherwise.
        $response = $this->filter($this->container(self::resolving(new Subject('alice', ['editor']))), Identity::asUser('alice'));

        self::assertSame(403, $response->getStatusCode());
    }

    public function test_a_resolver_failure_is_not_turned_into_a_role(): void
    {
        $failing = new class implements SubjectResolverContract {
            public function resolve(Request $request): ?Subject
            {
                throw new \RuntimeException('central database unreachable');
            }
        };

        $this->expectExceptionMessage('central database unreachable');

        $this->filter($this->container($failing), Identity::asUser('u-1'));
    }

    // ── Without one: exactly the old behaviour ──────────────────────────────

    public function test_with_no_resolver_the_store_assignments_decide_as_before(): void
    {
        $container = $this->container();

        self::assertSame(200, $this->filter($container, Identity::asUser('alice'))->getStatusCode());
        self::assertNull($this->passed?->attribute(Subject::ATTRIBUTE));

        self::assertSame(403, $this->filter($container, Identity::asUser('bob'))->getStatusCode());
    }

    public function test_a_resolver_returning_null_falls_back_to_the_store(): void
    {
        $container = $this->container(self::resolving(null));

        self::assertSame(200, $this->filter($container, Identity::asUser('alice'))->getStatusCode());
        self::assertSame(403, $this->filter($container, Identity::asUser('bob'))->getStatusCode());
    }

    // ── Refusals ────────────────────────────────────────────────────────────

    public function test_a_guest_is_unauthenticated_and_the_responder_is_told(): void
    {
        $container = $this->container(self::resolving(new Subject('u-1', ['owner'])), $this->responder(null));

        self::assertSame(401, $this->filter($container, Identity::guest())->getStatusCode());
        self::assertSame(401, $this->filter($container, null)->getStatusCode());
        self::assertSame(DenialReason::Unauthenticated, $this->denials[0]->reason);
        self::assertNull($this->denials[0]->subject);
    }

    public function test_configuration_faults_are_never_offered_to_the_responder(): void
    {
        $container = $this->container(responder: $this->responder(Response::html('page', 403)));

        self::assertSame(500, $this->filter($container, Identity::asUser('u-1'), object: '')->getStatusCode());
        self::assertSame([], $this->denials);
    }
}
