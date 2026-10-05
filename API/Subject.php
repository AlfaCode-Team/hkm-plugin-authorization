<?php

declare(strict_types=1);

namespace Plugins\Authorization\API;

/**
 * Who is asking, where, and which roles they hold THERE, as the application
 * itself knows it.
 *
 * Produced by a project's {@see Contracts\SubjectResolverContract}. The roles
 * are the application's own answer — typically read live from its membership
 * table — so the policy store only has to say what a ROLE may do, never who
 * holds it. That removes the second copy of "who is an admin" that a `g` row
 * would otherwise be, and with it the window in which the two disagree.
 *
 * `$domain` is where the roles were looked up (a tenant, an organisation, a
 * workspace). It is passed to the enforcer only when the loaded model has a
 * domain; under the default domain-less model the roles have ALREADY been
 * scoped by the resolver and a role's permissions are the same everywhere.
 *
 * An empty role list is a real answer: "this person holds nothing here". The
 * `can` filter refuses it as {@see DenialReason::NoRole} — distinct from a role
 * that lacks the permission, because a project usually wants to say different
 * things in the two cases.
 */
final readonly class Subject
{
    /** Request attribute the `can` filter attaches the resolved subject under. */
    public const string ATTRIBUTE = 'authz.subject';

    /** @var list<string> */
    public array $roles;

    /** @param iterable<mixed> $roles non-strings and blanks are dropped; duplicates collapse */
    public function __construct(
        public string $id,
        iterable $roles,
        public ?string $domain = null,
    ) {
        $clean = [];
        foreach ($roles as $role) {
            if (\is_string($role) && ($role = trim($role)) !== '') {
                $clean[$role] = true;
            }
        }

        $this->roles = array_keys($clean);
    }

    public function hasRole(string $role): bool
    {
        return \in_array($role, $this->roles, true);
    }

    /** True when the resolver found no role at all for this person here. */
    public function isRoleless(): bool
    {
        return $this->roles === [];
    }
}
