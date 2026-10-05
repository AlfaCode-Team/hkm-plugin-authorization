<?php

declare(strict_types=1);

namespace Plugins\Authorization\API\Contracts;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use Plugins\Authorization\API\Denial;

/**
 * IMPLEMENTED BY A PROJECT (optional): what a refusal from the `can` filter
 * looks like.
 *
 * Without one, the filter answers 401 (unauthenticated) or 403 with the
 * standard error envelope — right for an API, wrong for a page a person opened
 * in a browser, who should see a page that says what happened, or be sent to
 * the part of the application they CAN use.
 *
 * Return a Response to send it, or null to fall back to the default for that
 * denial. The responder decides how a refusal is PRESENTED, never whether it
 * happens: the filter has already refused, and nothing returned here reaches
 * the route's handler.
 */
interface DenialResponderContract
{
    public function respond(Request $request, Denial $denial): ?Response;
}
