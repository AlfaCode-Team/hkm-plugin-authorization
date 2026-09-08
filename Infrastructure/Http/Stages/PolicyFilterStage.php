<?php

declare(strict_types=1);

namespace Plugins\Authorization\Infrastructure\Http\Stages;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Http\Contracts\HttpStageContract;
use Plugins\Authorization\API\Contracts\AuthorizationServiceContract;

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
 * The stage enforces (subject = Identity->userId, object, action) against the
 * Casbin policy. FAIL-CLOSED: a guest, a missing enforcer (the route forgot to
 * require authorization.policy), or a deny all yield an error response —
 * never a pass-through.
 *
 * ── DOMAIN ──────────────────────────────────────────────────────────────────
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

        $identity = $request->identity();
        if ($identity === null || $identity->isGuest()) {
            return Response::unauthorized(trans_or('authorization::messages.auth.required', 'Authentication is required.'));
        }

        $container = $request->container();
        if ($container === null || !$container->has(AuthorizationServiceContract::class)) {
            // Policy module not loaded for this route → the declaration is
            // incomplete (missing "requires": ["authorization.policy"]).
            return Response::json(['error' => [
                'code'    => 'authorization.unavailable',
                'message' => trans_or('authorization::messages.policy.not_loaded', 'This route declares a policy filter but the authorization module is not loaded.'),
            ]], 500);
        }

        $authz = $container->make(AuthorizationServiceContract::class);

        if (!$authz instanceof AuthorizationServiceContract || !$this->allows($authz, $identity, $object, $action)) {
            return Response::forbidden(trans_or('authorization::messages.policy.forbidden', 'You are not allowed to perform this action.'));
        }

        return $next($request);
    }

    /**
     * Enforce with the domain when the model has one, without when it does not.
     *
     * Any failure is a DENY: this filter is fail-closed, and an enforcer that
     * cannot answer must not be read as an allow.
     */
    private function allows(
        AuthorizationServiceContract $authz,
        \AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity $identity,
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
