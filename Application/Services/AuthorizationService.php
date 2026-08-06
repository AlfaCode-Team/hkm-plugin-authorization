<?php

declare(strict_types=1);

namespace Plugins\Authorization\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Exceptions\ServiceException;
use Plugins\Authorization\API\Contracts\AuthorizationServiceContract;
use Plugins\Authorization\Engine\Enforcer;

/**
 * GDA service wrapping the Casbin Enforcer.
 *
 * The Enforcer is the only collaborator and stays internal to this plugin
 * (bound via bindInternal in the Provider). This class is the published
 * surface other modules reach through AuthorizationServiceContract.
 */
final class AuthorizationService implements AuthorizationServiceContract
{
    public function __construct(
        private readonly Enforcer $enforcer,
    ) {
    }

    /** Memoised model capability check. */
    private ?bool $domainsSupported = null;

    public function allows(string $subject, string $object, string $action, string ...$extra): bool
    {
        try {
            return $this->enforcer->enforce($subject, $object, $action, ...$extra);
        } catch (\Throwable $e) {
            throw new ServiceException(
                'authorization.enforce.failed',
                layer: 'service.authorization',
                context: ['subject' => $subject, 'object' => $object, 'action' => $action],
                previous: $e,
            );
        }
    }

    public function denies(string $subject, string $object, string $action, string ...$extra): bool
    {
        return !$this->allows($subject, $object, $action, ...$extra);
    }

    /**
     * Refuse a domain-scoped call when the loaded model cannot express domains.
     *
     * The shipped rbac_model.conf declares `g = _, _` and a matcher that never
     * mentions a domain. Passing a domain to addRoleForUserInDomain() against
     * that model does NOT scope the grant — the role matches in every domain,
     * which is cross-tenant privilege escalation, silently, while the calling
     * code looks correct.
     *
     * Failing loudly is the only safe response: a caller that asks for a scoped
     * grant must not receive a global one. Load
     * config/rbac_with_domains_model.conf (AUTHZ_MODEL_PATH) to enable them.
     */
    private function assertDomainsSupported(?string $domain, string $operation): void
    {
        if ($domain === null) {
            return;
        }

        if ($this->modelSupportsDomains()) {
            return;
        }

        throw new ServiceException(
            'authorization.domain.unsupported',
            layer: 'service.authorization',
            context: [
                'operation' => $operation,
                'domain'    => $domain,
                'hint'      => 'The loaded RBAC model is domain-less, so a domain-scoped grant would '
                             . 'apply GLOBALLY. Set AUTHZ_MODEL_PATH to config/rbac_with_domains_model.conf.',
            ],
        );
    }

    /** True when the model's role definition carries a third (domain) token. */
    private function modelSupportsDomains(): bool
    {
        if ($this->domainsSupported !== null) {
            return $this->domainsSupported;
        }

        try {
            $model  = $this->enforcer->getModel();
            $tokens = $model->model['g']['g']->tokens ?? [];

            return $this->domainsSupported = \count($tokens) >= 3;
        } catch (\Throwable) {
            // Cannot introspect the model — assume NOT domain-aware, which is
            // the fail-closed answer.
            return $this->domainsSupported = false;
        }
    }

    public function assignRole(string $user, string $role, ?string $domain = null): bool
    {
        $this->assertDomainsSupported($domain, 'assignRole');

        return $domain === null
            ? $this->enforcer->addRoleForUser($user, $role)
            : $this->enforcer->addRoleForUserInDomain($user, $role, $domain);
    }

    public function revokeRole(string $user, string $role, ?string $domain = null): bool
    {
        $this->assertDomainsSupported($domain, 'revokeRole');

        return $domain === null
            ? $this->enforcer->deleteRoleForUser($user, $role)
            : $this->enforcer->deleteRoleForUserInDomain($user, $role, $domain);
    }

    /** @return list<string> */
    public function rolesOf(string $user, ?string $domain = null): array
    {
        $this->assertDomainsSupported($domain, 'rolesOf');

        return $domain === null
            ? $this->enforcer->getRolesForUser($user)
            : $this->enforcer->getRolesForUserInDomain($user, $domain);
    }

    /** @return list<string> effective (own + role-inherited) "object:action" grants */
    public function permissionsOf(string $user, ?string $domain = null): array
    {
        $this->assertDomainsSupported($domain, 'permissionsOf');

        $rules = $domain === null
            ? $this->enforcer->getImplicitPermissionsForUser($user)
            : $this->enforcer->getImplicitPermissionsForUser($user, $domain);

        $permissions = [];
        foreach ($rules as $rule) {
            // Rule shape: [sub, obj, act] (+ optional extras) — flatten to obj:act.
            $object = (string) ($rule[1] ?? '');
            $action = (string) ($rule[2] ?? '');
            if ($object !== '' && $action !== '') {
                $permissions[$object . ':' . $action] = true;
            }
        }

        return array_keys($permissions);
    }

    public function grant(string $subject, string $object, string $action, string ...$extra): bool
    {
        return $this->enforcer->addPolicy($subject, $object, $action, ...$extra);
    }

    public function revoke(string $subject, string $object, string $action, string ...$extra): bool
    {
        return $this->enforcer->removePolicy($subject, $object, $action, ...$extra);
    }
}
