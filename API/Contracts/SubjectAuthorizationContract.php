<?php

declare(strict_types=1);

namespace Plugins\Authorization\API\Contracts;

use Plugins\Authorization\API\Subject;

/**
 * Published: what a {@see Subject}'s roles allow, by the loaded policy.
 *
 * The policy's `p` rows are checked for each of the subject's roles, and any
 * role that allows the action is enough. Role inheritance in the policy (`g`
 * rows between ROLES, e.g. `g, admin, editor`) still applies; `g` rows naming
 * users are simply never consulted, because the subject's roles came from the
 * application rather than from the store.
 *
 * A separate contract from {@see AuthorizationServiceContract} on purpose:
 * adding methods to that one would break every class that implements it.
 */
interface SubjectAuthorizationContract
{
    /** Whether any of the subject's roles may perform $action on $object. */
    public function allows(Subject $subject, string $object, string $action): bool;

    /**
     * The members of $permissions ("object:action") the subject holds, in the
     * order given.
     *
     * Asked of the matcher one by one rather than listed from the policy,
     * because a listing cannot expand a wildcard: `p, admin, *, *` lists as
     * "*:*", while this answers "payments:refund" correctly for an admin. Pass
     * the application's own catalogue — a sidebar, a set of buttons — and get
     * back exactly what to show.
     *
     * A permission is split at its LAST colon, so an object may contain one.
     *
     * @param  iterable<string> $permissions
     * @return list<string>
     */
    public function filter(Subject $subject, iterable $permissions): array;
}
