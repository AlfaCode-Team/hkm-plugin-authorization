<?php

declare(strict_types=1);

namespace Plugins\Authorization\API\Contracts;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use Plugins\Authorization\API\Subject;

/**
 * IMPLEMENTED BY A PROJECT (optional): who the `can` filter is judging.
 *
 * Bind it — a public `bind()`, from a module the request loads, usually an
 * essential one — and the filter stops reading role assignments from the
 * policy store. It asks this instead, and checks the policy for the ROLES it
 * returns:
 *
 *   policy store    →  what each role may do     (`p` rows: role, object, action)
 *   this resolver   →  which roles this person holds here, right now
 *
 * The usual reason to bind one is that the application already owns
 * memberships (a `user_tenants`-style table). Copying them into `g` rows means
 * two stores that must be written together, and a role removed in one but not
 * the other stays usable. Reading the application's own table on the request
 * makes a role change apply on the next request.
 *
 * The resolver also decides WHERE the person is judged. The default (no
 * resolver) is `Identity::$tenantId`, a value the kernel documents as a hint;
 * a project that judges against, say, the tenant owning the hostname does that
 * lookup here.
 *
 * Return:
 *   - a Subject           → judged on its roles (an empty list is refused as
 *                           DenialReason::NoRole);
 *   - null                → "not mine to answer": the filter falls back to the
 *                           policy store's own role assignments for the user,
 *                           exactly as when no resolver is bound.
 *
 * Throwing is not a refusal — it reaches ErrorStage as a server error, which
 * still denies the request. Do not catch a database failure and return an
 * empty role list: that would tell a working admin they have no role.
 */
interface SubjectResolverContract
{
    public function resolve(Request $request): ?Subject;
}
