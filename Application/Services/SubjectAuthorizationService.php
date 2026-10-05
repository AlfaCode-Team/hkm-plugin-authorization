<?php

declare(strict_types=1);

namespace Plugins\Authorization\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Exceptions\ServiceException;
use Plugins\Authorization\API\Contracts\SubjectAuthorizationContract;
use Plugins\Authorization\API\Subject;
use Plugins\Authorization\Engine\Enforcer;

/**
 * Checks the policy for the ROLES a project's resolver supplied.
 *
 * Each role is enforced as the request subject. That works on the shipped
 * matchers because `g(r.sub, p.sub)` is true when both are the same name (the
 * role manager short-circuits `name1 == name2`), and it still walks `g` rows
 * between roles, so a policy may say `g, admin, editor`.
 */
final class SubjectAuthorizationService implements SubjectAuthorizationContract
{
    /** Memoised: whether the model's request definition carries a domain. */
    private ?bool $domainAware = null;

    public function __construct(
        private readonly Enforcer $enforcer,
    ) {
    }

    public function allows(Subject $subject, string $object, string $action): bool
    {
        foreach ($subject->roles as $role) {
            if ($this->roleAllows($role, $subject->domain, $object, $action)) {
                return true;
            }
        }

        return false;
    }

    public function filter(Subject $subject, iterable $permissions): array
    {
        $held = [];

        foreach ($permissions as $permission) {
            if (!\is_string($permission) || isset($held[$permission])) {
                continue;
            }

            $at = strrpos($permission, ':');
            if ($at === false || $at === 0 || $at === \strlen($permission) - 1) {
                continue; // not "object:action" — nothing can grant it
            }

            if ($this->allows($subject, substr($permission, 0, $at), substr($permission, $at + 1))) {
                $held[$permission] = true;
            }
        }

        return array_keys($held);
    }

    private function roleAllows(string $role, ?string $domain, string $object, string $action): bool
    {
        if ($this->domainAware()) {
            // A domain model with no domain to judge in has nothing to match;
            // inventing one ('' or '*') would be choosing a scope for the caller.
            if ($domain === null || $domain === '') {
                return false;
            }

            $request = [$role, $domain, $object, $action];
        } else {
            // The resolver already scoped the roles to $domain; under a
            // domain-less model a role means the same thing everywhere.
            $request = [$role, $object, $action];
        }

        try {
            return $this->enforcer->enforce(...$request);
        } catch (\Throwable $e) {
            throw new ServiceException(
                'authorization.enforce.failed',
                layer: 'service.authorization',
                context: ['role' => $role, 'object' => $object, 'action' => $action],
                previous: $e,
            );
        }
    }

    /**
     * Read from the REQUEST definition (`r = sub, dom, obj, act`), which is
     * what enforce() is called against. The tokens are named (`r_dom`), so a
     * custom model with the domain in another position is still recognised.
     */
    private function domainAware(): bool
    {
        if ($this->domainAware !== null) {
            return $this->domainAware;
        }

        try {
            $tokens = $this->enforcer->getModel()['r']['r']->tokens ?? [];
        } catch (\Throwable) {
            $tokens = [];
        }

        return $this->domainAware = \in_array('r_dom', $tokens, true);
    }
}
