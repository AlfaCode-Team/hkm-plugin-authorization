<?php

declare(strict_types=1);

namespace Plugins\Authorization\API;

/** Why the `can` filter refused a request — see {@see Denial}. */
enum DenialReason: string
{
    /** No identity, or a guest. */
    case Unauthenticated = 'unauthenticated';

    /** Signed in, but the resolver found no role for them here. */
    case NoRole = 'no_role';

    /** They hold a role here, and no role they hold allows this. */
    case Forbidden = 'forbidden';
}
