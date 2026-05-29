<?php

declare(strict_types=1);

require __DIR__ . '/../src/Globiguard.php';

use GlobiGuard\Bootstrap;
use GlobiGuard\Transport;
use GlobiGuard\TrustWebhook;

Transport::validatePath('/v1/actions');
expectThrows(fn () => Transport::validatePath('https://evil.example/v1'));
expectThrows(fn () => Transport::validatePath('/v1/../secret'));

$registration = Bootstrap::installRegistration([
    'environment' => 'sandbox',
    'deploymentMode' => 'self_hosted',
    'issuerMode' => 'customer_issued',
    'installReporting' => 'opt_in',
], 'globiguard', '0.1.0', 'sdk', 'php');
assertTrue($registration['environment'] === 'sandbox', 'bootstrap environment');

$rawBody = '{"type":"globiguard.test"}';
$timestamp = (string) time();
$delivery = 'del_test';
$secret = 'whsec_test';
$signed = 'globiguard-hmac-sha256-v1.' . $delivery . '.' . $timestamp . '.globiguard.test.' . $rawBody;
$signature = 'v1=' . hash_hmac('sha256', $signed, $secret);
$result = TrustWebhook::verify([
    'x-globiguard-delivery-id' => $delivery,
    'x-globiguard-timestamp' => $timestamp,
    'x-globiguard-event-type' => 'globiguard.test',
    'x-globiguard-signature' => $signature,
], $rawBody, $secret);
assertTrue($result['ok'] === true, 'webhook verification');

echo "GlobiGuard PHP SDK smoke tests passed.\n";

function assertTrue(bool $condition, string $label): void
{
    if (!$condition) {
        throw new RuntimeException('Assertion failed: ' . $label);
    }
}

function expectThrows(callable $fn): void
{
    try {
        $fn();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException('Expected exception.');
}

