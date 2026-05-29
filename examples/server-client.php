<?php

declare(strict_types=1);

require __DIR__ . '/../src/Globiguard.php';

use GlobiGuard\Client;
use GlobiGuard\Credential;

$client = Client::server([
    'environment' => 'sandbox',
    'services' => ['controlPlane' => 'https://api.globiguard.com'],
    'credential' => Credential::secret('proj_example', 'ggsk_example_replace_me', 'sandbox'),
]);

$decision = $client->governedActions()->authorizeActionOrThrow([
    'actionType' => 'refund',
    'actor' => ['id' => 'user_123'],
    'target' => ['id' => 'order_456'],
    'reason' => 'Customer support refund approval',
]);

var_dump($decision);

