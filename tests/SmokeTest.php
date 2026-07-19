<?php

declare(strict_types=1);

require __DIR__ . '/../src/Globiguard.php';

use GlobiGuard\Bootstrap;
use GlobiGuard\Client;
use GlobiGuard\Credential;
use GlobiGuard\Entitlements;
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

$browser = Client::browser([
    'environment' => 'sandbox',
    'services' => ['controlPlane' => 'https://api.globiguard.com'],
    'credential' => Credential::publishable('proj_123', 'ggpk_test', 'sandbox'),
]);
expectThrows(fn () => $browser->policies()->create([]));
expectThrows(fn () => $browser->governedActions()->authorizeAction([]));
expectThrows(fn () => $browser->governedActions()->reviewQueue('queue_123', 'approve'));
expectThrows(fn () => $browser->governedActions()->exportEvidencePackage());

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

$entitlementToken = 'eyJhbGciOiJFZERTQSIsImtpZCI6ImtpZF90ZXN0IiwidHlwIjoiZ2xvYmlndWFyZC5lbnRpdGxlbWVudC52MSJ9.'
    . 'eyJtYW5pZmVzdFR5cGUiOiJnbG9iaWd1YXJkLmVudGl0bGVtZW50LnYxIiwibWFuaWZlc3RWZXJzaW9uIjoxLCJtYW5pZmVzdElkIjoibWFuaWZlc3RfMTIzIiwiaXNzdWVyIjoiaHR0cHM6Ly9hcGkuZ2xvYmlndWFyZC5jb20iLCJpc3N1ZWRBdCI6IjIwMjYtMDUtMjlUMTA6MDA6MDBaIiwibm90QmVmb3JlIjoiMjAyNi0wNS0yOVQxMDowMDowMFoiLCJleHBpcmVzQXQiOiIyMDI2LTA1LTMwVDEwOjAwOjAwWiIsInN1YmplY3QiOnsib3JnSWQiOiJvcmdfMTIzIiwid29ya3NwYWNlTmFtZSI6IkFjbWUiLCJvcmdTbHVnIjoiYWNtZSIsInByb2plY3RJZCI6InByb2pfMTIzIiwicHJvamVjdFNsdWciOiJtYWluIiwiZW52aXJvbm1lbnQiOiJzYW5kYm94IiwiZGVwbG95bWVudE1vZGUiOiJzZWxmX2hvc3RlZCJ9LCJjb21tZXJjaWFsIjp7ImNvbW1lcmNpYWxQbGFuIjoiR1JPV1RIIiwiYmlsbGluZ1N0YXR1cyI6IkFDVElWRSIsInBpbG90QWN0aXZlIjpmYWxzZX0sImVudGl0bGVtZW50cyI6eyJpbmNsdWRlZFF1ZXJpZXNQZXJNb250aCI6MTAwMDAsImZyYW1ld29ya1Nsb3RzIjozLCJvdmVyYWdlTW9kZSI6Ik1FVEVSRUQifX0.'
    . 'qJZVmhIyLBsSUmrFlpCzCytt6pUly5CZG7miWgxxZttuqXNnNWfleiSJ7ScK15AVhY0ZnLopSHZg4_uQbSi8CQ';
$entitlement = Entitlements::verifySignedManifest(
    $entitlementToken,
    ['kid_test' => '0EBi8A20QIJf5lwzzj98ZK1X8EzBJ2nli7rsMM8JXzc'],
    [
        'expectedIssuer' => 'https://api.globiguard.com',
        'expectedOrgId' => 'org_123',
        'expectedProjectId' => 'proj_123',
        'expectedEnvironment' => 'sandbox',
        'expectedDeploymentMode' => 'self_hosted',
        'now' => '2026-05-29T10:30:00Z',
    ],
);
assertTrue($entitlement['commercial']['commercialPlan'] === 'GROWTH', 'signed entitlement verification');
expectThrows(fn () => Entitlements::verifySignedManifest(
    $entitlementToken,
    ['kid_test' => '0EBi8A20QIJf5lwzzj98ZK1X8EzBJ2nli7rsMM8JXzc'],
    ['expectedOrgId' => 'org_other', 'now' => '2026-05-29T10:30:00Z'],
));

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

