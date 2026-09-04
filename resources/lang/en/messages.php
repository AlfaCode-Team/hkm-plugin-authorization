<?php

declare(strict_types=1);

/**
 * English copy for the Authorization plugin's user-facing denials.
 *
 * `policy.not_loaded` is a CONFIGURATION fault, not a user mistake — a route
 * named a policy filter the module was never loaded to answer. It is translated
 * anyway because it reaches a client in a response body like any other message;
 * it deliberately says nothing about which policy or which module version, for
 * the same reason the denials below do not say which check failed.
 */
return [
    'auth' => [
        'required' => 'Authentication is required.',
    ],
    'policy' => [
        'forbidden'  => 'You are not allowed to perform this action.',
        'not_loaded' => 'This route declares a policy filter but the authorization module is not loaded.',
    ],
];
