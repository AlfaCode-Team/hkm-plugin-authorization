<?php

declare(strict_types=1);

/**
 * Copie française des refus du plugin Authorization.
 *
 * Les clés doivent rester identiques à lang/en/messages.php : une clé manquante
 * n'échoue pas, elle affiche l'anglais au milieu d'une page française.
 */
return [
    'auth' => [
        'required' => 'Une authentification est requise.',
    ],
    'policy' => [
        'forbidden'  => "Vous n'êtes pas autorisé à effectuer cette action.",
        'not_loaded' => "Cette route déclare un filtre de politique mais le module d'autorisation n'est pas chargé.",
    ],
];
