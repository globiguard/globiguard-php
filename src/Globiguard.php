<?php

declare(strict_types=1);

namespace GlobiGuard;

use RuntimeException;

final class EnvironmentName
{
    public const LOCAL = 'local';
    public const SANDBOX = 'sandbox';
    public const LIVE = 'live';

    public static function isValid(string $value): bool
    {
        return in_array($value, [self::LOCAL, self::SANDBOX, self::LIVE], true);
    }
}

final class Credential
{
    private function __construct(
        public readonly string $kind,
        public readonly ?string $projectId,
        public readonly ?string $token,
        public readonly string $environment,
    ) {
    }

    public static function secret(string $projectId, string $token, string $environment): self
    {
        return new self('secret', $projectId, $token, $environment);
    }

    public static function publishable(string $projectId, string $token, string $environment): self
    {
        return new self('publishable', $projectId, $token, $environment);
    }

    public static function local(?string $token = null): self
    {
        return new self('local', null, $token, EnvironmentName::LOCAL);
    }
}

final class Client
{
    private function __construct(private readonly Transport $transport)
    {
    }

    /** @param array{environment:string,services:array<string,string>,credential:Credential} $options */
    public static function server(array $options): self
    {
        if ($options['credential']->kind === 'publishable') {
            throw new RuntimeException('Server clients require secret or local credentials.');
        }
        return new self(new Transport($options));
    }

    /** @param array{environment:string,services:array<string,string>,credential:Credential} $options */
    public static function browser(array $options): self
    {
        if ($options['credential']->kind === 'secret') {
            throw new RuntimeException('Browser clients cannot use secret credentials.');
        }
        return new self(new Transport($options));
    }

    public function actions(): ResourceClient { return new ResourceClient($this->transport, '/v1/actions'); }
    public function audit(): ResourceClient { return new ResourceClient($this->transport, '/v1/audit'); }
    public function installs(): ResourceClient { return new ResourceClient($this->transport, '/v1/installs'); }
    public function orgs(): ResourceClient { return new ResourceClient($this->transport, '/v1/orgs'); }
    public function policies(): ResourceClient { return new ResourceClient($this->transport, '/v1/policies'); }
    public function queue(): ResourceClient { return new ResourceClient($this->transport, '/v1/queue'); }
    public function workflows(): ResourceClient { return new ResourceClient($this->transport, '/v1/workflows'); }
    public function governedActions(): GovernedActions { return new GovernedActions($this->transport); }
}

final class Transport
{
    private const RESERVED_HEADERS = [
        'x-globiguard-project-id',
        'x-globiguard-secret-key',
        'x-globiguard-publishable-key',
        'x-globiguard-local-mode',
        'x-globiguard-local-token',
        'x-globiguard-client',
        'x-globiguard-environment',
    ];

    private readonly string $environment;
    /** @var array<string,string> */
    private readonly array $services;
    private readonly Credential $credential;

    /** @param array{environment:string,services:array<string,string>,credential:Credential} $options */
    public function __construct(array $options)
    {
        $this->environment = $options['environment'];
        $this->services = $options['services'];
        $this->credential = $options['credential'];
        if (!EnvironmentName::isValid($this->environment)) {
            throw new RuntimeException('Environment must be local, sandbox, or live.');
        }
        if ($this->credential->environment !== $this->environment) {
            throw new RuntimeException('Credential environment must match client environment.');
        }
        $baseUrl = $this->services['controlPlane'] ?? null;
        if (!$baseUrl) {
            throw new RuntimeException('services.controlPlane is required.');
        }
        $host = parse_url($baseUrl, PHP_URL_HOST);
        $scheme = parse_url($baseUrl, PHP_URL_SCHEME);
        if ($this->environment !== EnvironmentName::LOCAL && $scheme !== 'https') {
            throw new RuntimeException('HTTPS is required outside local.');
        }
        if ($this->credential->kind === 'local' && !in_array($host, ['localhost', '127.0.0.1', '::1'], true)) {
            throw new RuntimeException('Local credentials require localhost or loopback URLs.');
        }
    }

    /** @param array<string,string> $headers */
    public function request(string $method, string $path, ?array $body = null, array $headers = []): array
    {
        self::validatePath($path);
        foreach ($headers as $name => $_) {
            if (in_array(strtolower($name), self::RESERVED_HEADERS, true)) {
                throw new RuntimeException('Reserved GlobiGuard header cannot be overridden: ' . $name);
            }
        }
        $url = rtrim($this->services['controlPlane'], '/') . $path;
        $requestHeaders = array_merge($this->authHeaders(), $headers);
        $headerLines = [];
        foreach ($requestHeaders as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }
        $content = null;
        if ($body !== null) {
            $content = json_encode($body, JSON_THROW_ON_ERROR);
            $headerLines[] = 'content-type: application/json';
        }
        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $headerLines),
                'content' => $content ?? '',
                'timeout' => 30,
                'ignore_errors' => true,
            ],
        ]);
        $response = file_get_contents($url, false, $context);
        if ($response === false) {
            throw new RuntimeException('GlobiGuard request failed.');
        }
        return $response === '' ? [] : json_decode($response, true, 512, JSON_THROW_ON_ERROR);
    }

    /** @return array<string,string> */
    public function authHeaders(): array
    {
        $headers = [
            'x-globiguard-client' => 'globiguard-php/0.1.0',
            'x-globiguard-environment' => $this->environment,
        ];
        if ($this->credential->kind === 'local') {
            $headers['x-globiguard-local-mode'] = 'true';
            if ($this->credential->token) {
                $headers['x-globiguard-local-token'] = $this->credential->token;
            }
            return $headers;
        }
        $headers['x-globiguard-project-id'] = self::requireValue($this->credential->projectId, 'project id');
        $headers[$this->credential->kind === 'secret' ? 'x-globiguard-secret-key' : 'x-globiguard-publishable-key'] = self::requireValue($this->credential->token, 'credential token');
        return $headers;
    }

    public static function validatePath(string $path): void
    {
        if (!str_starts_with($path, '/')) {
            throw new RuntimeException('Request path must start with /.');
        }
        if (str_starts_with($path, '//') || str_contains($path, '\\') || str_contains($path, '?') || str_contains($path, '#') || preg_match('/%(?![0-9A-Fa-f]{2})/', $path)) {
            throw new RuntimeException('Unsafe request path.');
        }
        foreach (explode('/', $path) as $segment) {
            if ($segment === '.' || $segment === '..') {
                throw new RuntimeException('Dot segments are not allowed.');
            }
        }
    }

    private static function requireValue(?string $value, string $label): string
    {
        if ($value === null || $value === '') {
            throw new RuntimeException('Missing ' . $label . '.');
        }
        return $value;
    }
}

final class ResourceClient
{
    public function __construct(private readonly Transport $transport, private readonly string $basePath)
    {
    }

    public function list(): array { return $this->transport->request('GET', $this->basePath); }
    public function get(string $id): array { return $this->transport->request('GET', $this->basePath . '/' . rawurlencode($id)); }
    public function create(array $body): array { return $this->transport->request('POST', $this->basePath, $body); }
    public function post(string $suffix, array $body): array { return $this->transport->request('POST', $this->basePath . '/' . ltrim($suffix, '/'), $body); }
}

final class GovernedActions
{
    public function __construct(private readonly Transport $transport)
    {
    }

    public function authorizeActionOrThrow(array $body, ?string $idempotencyKey = null, ?string $correlationId = null): array
    {
        $headers = [];
        if ($idempotencyKey) {
            $headers['Idempotency-Key'] = $idempotencyKey;
        }
        if ($correlationId) {
            $headers['x-correlation-id'] = $correlationId;
        }
        $result = $this->transport->request('POST', '/v1/actions/authorize', $body, $headers);
        if (($result['decision'] ?? null) === 'BLOCK') {
            throw new RuntimeException('GlobiGuard blocked the governed action.');
        }
        return $result;
    }
}

final class TrustWebhook
{
    /** @param array<string,string> $headers */
    public static function verify(array $headers, string $rawBody, string $signingSecret, int $toleranceSeconds = 300): array
    {
        $normalized = [];
        foreach ($headers as $name => $value) {
            $normalized[strtolower($name)] = $value;
        }
        $delivery = $normalized['x-globiguard-delivery-id'] ?? null;
        $timestamp = $normalized['x-globiguard-timestamp'] ?? null;
        $eventType = $normalized['x-globiguard-event-type'] ?? null;
        $signature = $normalized['x-globiguard-signature'] ?? null;
        if (!$delivery || !$timestamp || !$eventType || !$signature) {
            return ['ok' => false, 'error' => 'Missing required webhook headers.'];
        }
        if (abs(time() - (int) $timestamp) > $toleranceSeconds) {
            return ['ok' => false, 'error' => 'Webhook timestamp is outside the replay window.'];
        }
        $signed = 'globiguard-hmac-sha256-v1.' . $delivery . '.' . $timestamp . '.' . $eventType . '.' . $rawBody;
        $expected = 'v1=' . hash_hmac('sha256', $signed, $signingSecret);
        if (!hash_equals($expected, $signature)) {
            return ['ok' => false, 'error' => 'Invalid webhook signature.'];
        }
        return ['ok' => true, 'envelope' => json_decode($rawBody, true, 512, JSON_THROW_ON_ERROR)];
    }
}

final class Bootstrap
{
    public static function installRegistration(array $profile, string $packageName, string $packageVersion, string $integrationKind, string $runtimeKind): array
    {
        self::validateProfile($profile);
        return [
            'environment' => $profile['environment'],
            'deploymentMode' => $profile['deploymentMode'],
            'issuerMode' => $profile['issuerMode'],
            'installReporting' => $profile['installReporting'],
            'installLabel' => $profile['installLabel'] ?? null,
            'package' => ['name' => $packageName, 'version' => $packageVersion],
            'integration' => ['kind' => $integrationKind, 'runtime' => $runtimeKind],
        ];
    }

    private static function validateProfile(array $profile): void
    {
        if (!EnvironmentName::isValid($profile['environment'] ?? '')) {
            throw new RuntimeException('Invalid environment.');
        }
        if (($profile['deploymentMode'] ?? '') === 'hosted' && ($profile['issuerMode'] ?? '') !== 'globiguard_issued') {
            throw new RuntimeException('Hosted deployments require globiguard_issued issuer mode.');
        }
        if (in_array($profile['deploymentMode'] ?? '', ['self_hosted', 'sovereign'], true)) {
            if (($profile['issuerMode'] ?? '') !== 'customer_issued') {
                throw new RuntimeException('Self-hosted and sovereign deployments require customer_issued issuer mode.');
            }
            if (!in_array($profile['installReporting'] ?? '', ['opt_in', 'disabled'], true)) {
                throw new RuntimeException('Self-hosted and sovereign install reporting must be opt_in or disabled.');
            }
        }
    }
}

final class Entitlements
{
    /** @param array<string,string> $publicKeysById base64url Ed25519 public keys keyed by kid */
    public static function verifySignedManifest(string $compactJws, array $publicKeysById): array
    {
        $parts = explode('.', $compactJws);
        if (count($parts) !== 3) {
            throw new RuntimeException('Entitlement manifest must be compact JWS.');
        }
        $header = json_decode(self::base64UrlDecode($parts[0]), true, 512, JSON_THROW_ON_ERROR);
        if (($header['alg'] ?? null) !== 'EdDSA') {
            throw new RuntimeException('Entitlement manifest must use EdDSA.');
        }
        $kid = $header['kid'] ?? null;
        if (!$kid || !isset($publicKeysById[$kid])) {
            throw new RuntimeException('Unknown entitlement signing key.');
        }
        $signature = self::base64UrlDecode($parts[2]);
        $publicKey = self::base64UrlDecode($publicKeysById[$kid]);
        $signingInput = $parts[0] . '.' . $parts[1];
        if (!sodium_crypto_sign_verify_detached($signature, $signingInput, $publicKey)) {
            throw new RuntimeException('Invalid entitlement manifest signature.');
        }
        $payload = json_decode(self::base64UrlDecode($parts[1]), true, 512, JSON_THROW_ON_ERROR);
        if (($payload['schema'] ?? null) !== 'globiguard.entitlement_manifest.v1') {
            throw new RuntimeException('Unsupported entitlement manifest schema.');
        }
        $now = time();
        if (isset($payload['nbf']) && (int) $payload['nbf'] > $now) {
            throw new RuntimeException('Entitlement manifest is not active yet.');
        }
        if (isset($payload['exp']) && (int) $payload['exp'] <= $now) {
            throw new RuntimeException('Entitlement manifest is expired.');
        }
        return $payload;
    }

    private static function base64UrlDecode(string $value): string
    {
        return base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true) ?: throw new RuntimeException('Invalid base64url value.');
    }
}

