<?php

declare(strict_types=1);

namespace Plugins\Authorization\Infrastructure\Http\Stages;

use AlfacodeTeam\PhpServicePlatform\Kernel\Container\ModuleContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Http\Contracts\HttpStageContract;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\Authorization\API\Contracts\AuthorizationServiceContract;
use Plugins\Authorization\API\Contracts\DenialResponderContract;
use Plugins\Authorization\API\Contracts\SubjectAuthorizationContract;
use Plugins\Authorization\API\Contracts\SubjectResolverContract;
use Plugins\Authorization\API\Denial;
use Plugins\Authorization\API\DenialReason;
use Plugins\Authorization\API\Subject;

/**
 * PolicyFilterStage — the declarative `can` route filter.
 *
 * A route opts into policy-backed protection in its module.json / proj.json:
 *
 *   { "method": "PUT", "path": "/api/users/{id}",
 *     "handler": "…",
 *     "filters":  ["auth", "can:users,edit"],
 *     "requires": ["authorization.policy"] }
 *
 * FAIL-CLOSED: a guest, a missing enforcer (the route forgot to require
 * authorization.policy), or a deny all yield an error response — never a
 * pass-through.
 *
 * ── WHO IS JUDGED ───────────────────────────────────────────────────────────
 * When the request's container holds a {@see SubjectResolverContract} (bound
 * by the project), the filter asks it for the Subject and checks the policy for
 * the ROLES it returns, via {@see SubjectAuthorizationContract}. The resolved
 * Subject is attached to the request as {@see Subject::ATTRIBUTE}, so the
 * handler can ask the same question again (which buttons to show) without
 * resolving it twice.
 *
 * With no resolver — or one that returns null — the filter behaves exactly as
 * it always has: subject = Identity->userId, and role assignments come from the
 * policy store's own `g` rows.
 *
 * ── HOW A REFUSAL LOOKS ─────────────────────────────────────────────────────
 * A bound {@see DenialResponderContract} is offered every refusal first; a null
 * from it falls back to the default 401/403. Configuration faults (a malformed
 * declaration, the module not loaded) are never offered to it: they are bugs,
 * not decisions about a person.
 *
 * ── DOMAIN (legacy path) ────────────────────────────────────────────────────
 * Under a domain-aware model the request definition is `r = sub, dom, obj, act`,
 * so a three-argument enforce is one value short and the matcher evaluates
 * against a request it was not written for. The tenant on the Identity is the
 * domain, and it is passed ONLY when the loaded model actually declares one —
 * appending it to a domain-less request would be the mirror mistake.
 *
 * The capability question is asked of the SERVICE rather than answered here:
 * `rolesOf()` is refused with `authorization.domain.unsupported` when the model
 * cannot carry a domain, so one throwaway read against a subject that cannot
 * exist settles it, once per request.
 */
final class PolicyFilterStage implements HttpStageContract
{
    public function handle(Request $request, callable $next): Response
    {
        $args   = (array) ($request->attribute('filter_args')['can'] ?? []);
        $object = trim((string) ($args[0] ?? ''));
        $action = trim((string) ($args[1] ?? ''));

        if ($object === '' || $action === '') {
            // A malformed filter declaration is a config bug — fail closed loudly.
            return Response::serverError();
        }

        $container = $request->container();

        $identity = $request->identity();
        if ($identity === null || $identity->isGuest()) {
            return $this->refuse($request, $container, new Denial(DenialReason::Unauthenticated, $object, $action));
        }

        if ($container === null || !$container->has(AuthorizationServiceContract::class)) {
            // Policy module not loaded for this route → the declaration is
            // incomplete (missing "requires": ["authorization.policy"]).
            return Response::json(['error' => [
                'code'    => 'authorization.unavailable',
                'message' => trans_or('authorization::messages.policy.not_loaded', 'This route declares a policy filter but the authorization module is not loaded.'),
            ]], 500);
        }

        // A resolver failure is NOT caught: it reaches ErrorStage as a 500,
        // which still refuses the request, and does not tell a working admin
        // they hold no role because a database was briefly unreachable.
        $subject = $container->has(SubjectResolverContract::class)
            ? $container->make(SubjectResolverContract::class)->resolve($request)
            : null;

        if ($subject !== null) {
            if ($subject->isRoleless()) {
                return $this->refuse($request, $container, new Denial(DenialReason::NoRole, $object, $action, $subject));
            }

            if (!$this->subjectAllows($container, $subject, $object, $action)) {
                return $this->refuse($request, $container, new Denial(DenialReason::Forbidden, $object, $action, $subject));
            }

            return $next($request->withAttribute(Subject::ATTRIBUTE, $subject));
        }

        $authz = $container->make(AuthorizationServiceContract::class);

        if (!$authz instanceof AuthorizationServiceContract || !$this->allows($authz, $identity, $object, $action)) {
            return $this->refuse($request, $container, new Denial(DenialReason::Forbidden, $object, $action));
        }

        return $next($request);
    }

    /** The project's answer when it has one, the standard envelope otherwise. */
    private function refuse(Request $request, ?ModuleContainer $container, Denial $denial): Response
    {
        if ($container !== null && $container->has(DenialResponderContract::class)) {
            $response = $container->make(DenialResponderContract::class)->respond($request, $denial);

            if ($response !== null) {
                return $response;
            }
        }

        return $denial->reason === DenialReason::Unauthenticated
            ? Response::unauthorized(trans_or('authorization::messages.auth.required', 'Authentication is required.'))
            : Response::forbidden(trans_or('authorization::messages.policy.forbidden', 'You are not allowed to perform this action.'));
    }

    /** Any failure is a DENY, as on the legacy path. */
    private function subjectAllows(ModuleContainer $container, Subject $subject, string $object, string $action): bool
    {
        try {
            $authz = $container->make(SubjectAuthorizationContract::class);

            return $authz instanceof SubjectAuthorizationContract && $authz->allows($subject, $object, $action);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Enforce with the domain when the model has one, without when it does not.
     *
     * Any failure is a DENY: this filter is fail-closed, and an enforcer that
     * cannot answer must not be read as an allow.
     */
    private function allows(
        AuthorizationServiceContract $authz,
        Identity $identity,
        string $object,
        string $action,
    ): bool {
        $domain = $identity->tenantId;

        try {
            if ($domain !== '' && $this->domainAware($authz, $domain)) {
                return $authz->allows($identity->userId, $domain, $object, $action);
            }

            return $authz->allows($identity->userId, $object, $action);
        } catch (\Throwable) {
            return false;
        }
    }

    /** One read against a subject no account can hold; the service refuses if the model is domain-less. */
    private function domainAware(AuthorizationServiceContract $authz, string $domain): bool
    {
        try {
            $authz->rolesOf('__can_filter_probe__', $domain);

            return true;
        } catch (\Throwable) {
            return false;
        }
    }
}
