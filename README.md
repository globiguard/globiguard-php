# globiguard-php

Official dependency-minimal PHP SDK for GlobiGuard.

The package has no Composer runtime package dependencies. It uses PHP built-ins plus required extensions (`json` and `sodium`) for HTTP, HMAC, JSON, and Ed25519 entitlement verification.

## Install

```bash
composer require globiguard/globiguard
```

## Server client

```php
use GlobiGuard\Client;
use GlobiGuard\Credential;

$client = Client::server([
    'environment' => 'sandbox',
    'services' => ['controlPlane' => 'https://api.globiguard.com'],
    'credential' => Credential::secret('proj_example', 'ggsk_example_replace_me', 'sandbox'),
]);

$decision = $client->governedActions()->authorizeActionOrThrow([
    'context' => [
        'actionType' => 'refund.create',
        'destination' => [
            'type' => 'custom',
            'name' => 'payments-production',
        ],
        'dataClasses' => ['CONFIDENTIAL'],
        'actor' => [
            'id' => 'support-agent-123',
            'type' => 'agent',
        ],
        'purpose' => 'Resolve an approved customer escalation',
        'correlationId' => 'case_456',
        'idempotencyKey' => 'case_456:refund:v1',
    ],
]);
```

The governed client also exposes approval polling, every queue review
transition, evidence export, evidence-package summaries, and incident replay.
`QUEUE` and `BLOCK` stop the authorize-or-throw path before the business action.

## Webhooks

Pass the exact raw request body string from the framework. Do not parse and re-serialize JSON before verification.

```php
$result = \GlobiGuard\TrustWebhook::verify($headers, $rawBody, 'whsec_example_replace_me');
if (!$result['ok']) {
    throw new RuntimeException($result['error']);
}
```

## Development

```bash
composer validate --strict
php -l src/Globiguard.php
php tests/SmokeTest.php
```
