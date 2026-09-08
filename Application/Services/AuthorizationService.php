<?php

declare(strict_types=1);

namespace Plugins\Authorization\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Exceptions\ServiceException;
use Plugins\Authorization\API\Contracts\AuthorizationServiceContract;
use Plugins\Authorization\Engine\Enforcer;
use Plugins\Authorization\Engine\Persist\Adapters\FileAdapter;

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

    /**
     * True when the model's role definition carries a third (domain) token.
     *
     * `$model['g']['g']`, NOT `$model->model['g']['g']`: Model extends Policy,
     * which keeps its assertions in a PROTECTED `$items` exposed through
     * ArrayAccess. There is no `model` property, so the old expression was
     * always null — the count was 0 and this returned false for EVERY model,
     * including the domain-aware one. Every domain-scoped call was refused no
     * matter how the plugin was configured.
     */
    private function modelSupportsDomains(): bool
    {
        if ($this->domainsSupported !== null) {
            return $this->domainsSupported;
        }

        try {
            $tokens = $this->enforcer->getModel()['g']['g']->tokens ?? [];

            return $this->domainsSupported = \count($tokens) >= 3;
        } catch (\Throwable) {
            // Cannot introspect the model — assume NOT domain-aware, which is
            // the fail-closed answer.
            return $this->domainsSupported = false;
        }
    }

    /**
     * Refuse a WRITE when the policy store cannot accept one.
     *
     * With AUTHZ_POLICY_FILE set the enforcer runs on Casbin's FileAdapter,
     * whose addPolicy/removePolicy throw NotImplementedException. Letting that
     * escape would put a vendor exception through the service boundary and tell
     * the caller nothing about why; this names the cause and the fix instead.
     *
     * Checked up front rather than caught afterwards so nothing is half-applied
     * — assignRole and grant both reach the enforcer more than once.
     */
    private function assertWritable(string $operation): void
    {
        if (!$this->readOnly()) {
            return;
        }

        throw new ServiceException(
            'authorization.store.read_only',
            layer: 'service.authorization',
            context: [
                'operation' => $operation,
                'hint'      => 'The policy store is a FILE (AUTHZ_POLICY_FILE), which Casbin '
                             . 'cannot write rule-by-rule. Edit the CSV and redeploy, or unset '
                             . 'AUTHZ_POLICY_FILE to use the policy table.',
            ],
        );
    }

    /** Memoised: whether the active adapter rejects per-rule writes. */
    private ?bool $readOnly = null;

    private function readOnly(): bool
    {
        if ($this->readOnly !== null) {
            return $this->readOnly;
        }

        try {
            return $this->readOnly = $this->enforcer->getAdapter() instanceof FileAdapter;
        } catch (\Throwable) {
            // Cannot tell — assume writable, so a working deployment is never
            // refused a write it could have performed. A genuinely read-only
            // adapter still raises from the engine.
            return $this->readOnly = false;
        }
    }

    /** Memoised: [objectIndex, actionIndex] within a policy rule. */
    private ?array $policyColumns = null;

    /**
     * Where the object and action actually sit in a policy rule.
     *
     * The rule is a positional list shaped by the model's policy_definition, so
     * `p = sub, obj, act` puts them at 1 and 2 while `p = sub, dom, obj, act`
     * puts them at 2 and 3. This used to be hardcoded to 1 and 2, which under a
     * domain-aware model returned "<domain>:<object>" — `p, admin, *, tenancy,
     * admin` came back as the permission "*:tenancy" instead of "tenancy:admin".
     *
     * The tokens are NAMED (p_sub, p_dom, p_obj, p_act), so the positions are
     * looked up rather than assumed, and any policy_definition works — including
     * ones this plugin does not ship. The 1/2 fallback is for a model whose
     * tokens cannot be read at all.
     *
     * @return array{0: int, 1: int}
     */
    private function policyColumns(): array
    {
        if ($this->policyColumns !== null) {
            return $this->policyColumns;
        }

        try {
            $tokens = $this->enforcer->getModel()['p']['p']->tokens ?? [];
        } catch (\Throwable) {
            $tokens = [];
        }

        $objectAt = array_search('p_obj', $tokens, true);
        $actionAt = array_search('p_act', $tokens, true);

        return $this->policyColumns = [
            \is_int($objectAt) ? $objectAt : 1,
            \is_int($actionAt) ? $actionAt : 2,
        ];
    }

    public function assignRole(string $user, string $role, ?string $domain = null): bool
    {
        $this->assertDomainsSupported($domain, 'assignRole');
        $this->assertWritable('assignRole');

        return $domain === null
            ? $this->enforcer->addRoleForUser($user, $role)
            : $this->enforcer->addRoleForUserInDomain($user, $role, $domain);
    }

    public function revokeRole(string $user, string $role, ?string $domain = null): bool
    {
        $this->assertDomainsSupported($domain, 'revokeRole');
        $this->assertWritable('revokeRole');

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

    /**
     * Effective (own + role-inherited) "object:action" grants.
     *
     * CAVEAT, measured: when a DOMAIN is passed, the engine's
     * getImplicitPermissionsForUser() selects policies whose domain equals it
     * exactly. A policy written with `*` — which the MATCHER honours, so
     * allows() returns true for it — is skipped here. The list therefore
     * under-reports globally-scoped permissions rather than over-reporting
     * them, which is the safe direction for something that is displayed rather
     * than enforced. allows() remains the authority on what a subject may do.
     *
     * @return list<string>
     */
    public function permissionsOf(string $user, ?string $domain = null): array
    {
        $this->assertDomainsSupported($domain, 'permissionsOf');

        $rules = $domain === null
            ? $this->enforcer->getImplicitPermissionsForUser($user)
            : $this->enforcer->getImplicitPermissionsForUser($user, $domain);

        [$objectAt, $actionAt] = $this->policyColumns();

        $permissions = [];
        foreach ($rules as $rule) {
            $object = (string) ($rule[$objectAt] ?? '');
            $action = (string) ($rule[$actionAt] ?? '');
            if ($object !== '' && $action !== '') {
                $permissions[$object . ':' . $action] = true;
            }
        }

        return array_keys($permissions);
    }

    public function grant(string $subject, string $object, string $action, string ...$extra): bool
    {
        $this->assertWritable('grant');

        return $this->enforcer->addPolicy($subject, $object, $action, ...$extra);
    }

    public function revoke(string $subject, string $object, string $action, string ...$extra): bool
    {
        $this->assertWritable('revoke');

        return $this->enforcer->removePolicy($subject, $object, $action, ...$extra);
    }
}
