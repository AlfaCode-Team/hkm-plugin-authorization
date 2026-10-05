<?php

declare(strict_types=1);

namespace Plugins\Authorization\API;

/**
 * A refusal by the `can` filter, handed to a project's
 * {@see Contracts\DenialResponderContract} so it can answer in its own terms.
 *
 * `$subject` is null when the reason is {@see DenialReason::Unauthenticated},
 * and when no resolver is bound (the filter then judged the Identity directly).
 */
final readonly class Denial
{
    public function __construct(
        public DenialReason $reason,
        public string $object,
        public string $action,
        public ?Subject $subject = null,
    ) {
    }

    /** "object:action" — the permission that was asked for. */
    public function permission(): string
    {
        return $this->object . ':' . $this->action;
    }
}
