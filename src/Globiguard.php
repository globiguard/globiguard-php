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
    private function __construct(
        private readonly Transport $transport,
        private readonly bool $readOnly,
    )
    {
    }

    /** @param array{environment:string,services:array<string,string>,credential:Credential} $options */
    public static function server(array $options): self
    {
        if ($options['credential']->kind === 'publishable') {
            throw new RuntimeException('Server clients require secret or local credentials.');
        }
        return new self(new Transport($options), false);
    }

    /** @param array{environment:string,services:array<string,string>,credential:Credential} $options */
    public static function browser(array $options): self
    {
        if ($options['credential']->kind === 'secret') {
            throw new RuntimeException('Browser clients cannot use secret credentials.');
        }
        return new self(new Transport($options), true);
    }

    public function actions(): ResourceClient { return new ResourceClient($this->transport, '/v1/actions', $this->readOnly); }
    public function audit(): ResourceClient { return new ResourceClient($this->transport, '/v1/audit', $this->readOnly); }
    public function installs(): ResourceClient { return new ResourceClient($this->transport, '/v1/installs', $this->readOnly); }
    public function orgs(): ResourceClient { return new ResourceClient($this->transport, '/v1/orgs', $this->readOnly); }
    public function policies(): ResourceClient { return new ResourceClient($this->transport, '/v1/policies', $this->readOnly); }
    public function queue(): ResourceClient { return new ResourceClient($this->transport, '/v1/queue', $this->readOnly); }
    public function workflows(): ResourceClient { return new ResourceClient($this->transport, '/v1/workflows', $this->readOnly); }
    public function governedActions(): GovernedActions { return new GovernedActions($this->transport, $this->readOnly); }
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
    public function request(string $method, string $path, ?array $body = null, array $headers = [], array $query = []): array
    {
        self::validatePath($path);
        foreach ($headers as $name => $_) {
            if (in_array(strtolower($name), self::RESERVED_HEADERS, true)) {
                throw new RuntimeException('Reserved GlobiGuard header cannot be overridden: ' . $name);
            }
        }
        $query = array_filter(
            $query,
            static fn (mixed $value): bool => $value !== null && $value !== ''
        );
        $url = rtrim($this->services['controlPlane'], '/') . $path;
        if ($query !== []) {
            $url .= '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        }
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
        $response = @file_get_contents($url, false, $context);
        if ($response === false) {
            throw new RuntimeException('GlobiGuard request failed.');
        }
        
        // Check HTTP status code
        if (isset($http_response_header)) {
            $statusLine = $http_response_header[0];
            if (preg_match('/HTTP\/[\d.]+\s+(\d{3})/', $statusLine, $matches)) {
                $statusCode = (int)$matches[1];
                if ($statusCode < 200 || $statusCode >= 300) {
                    throw new RuntimeException("GlobiGuard request failed with HTTP {$statusCode}.");
                }
            }
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
        if (str_starts_with($path, '//') || str_contains($path, '//') || str_contains($path, '\\') || str_contains($path, '?') || str_contains($path, '#') || preg_match('/%(?![0-9A-Fa-f]{2})/', $path)) {
            throw new RuntimeException('Unsafe request path.');
        }
        foreach (explode('/', $path) as $segment) {
            $decoded = rawurldecode($segment);
            if ($decoded === '.' || $decoded === '..' || str_contains($decoded, '/') || str_contains($decoded, '\\')) {
                throw new RuntimeException('Encoded separators and dot segments are not allowed.');
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
    public function __construct(
        private readonly Transport $transport,
        private readonly string $basePath,
        private readonly bool $readOnly,
    )
    {
    }

    public function list(): array { return $this->transport->request('GET', $this->basePath); }
    public function get(string $id): array { return $this->transport->request('GET', $this->basePath . '/' . rawurlencode($id)); }
    public function create(array $body): array
    {
        $this->requireWrite('Resource creation');
        return $this->transport->request('POST', $this->basePath, $body);
    }

    public function post(string $suffix, array $body): array
    {
        $this->requireWrite('Resource mutation');
        return $this->transport->request('POST', $this->basePath . '/' . rawurlencode(ltrim($suffix, '/')), $body);
    }

    private function requireWrite(string $operation): void
    {
        if ($this->readOnly) {
            throw new RuntimeException($operation . ' requires a server client.');
        }
    }
}

final class GovernedActions
{
    public function __construct(
        private readonly Transport $transport,
        private readonly bool $readOnly,
    )
    {
    }

    public function authorizeActionOrThrow(array $body): array
    {
        $result = $this->authorizeAction($body);
        $decision = $result['decision'] ?? null;
        if (in_array($decision, ['ALLOW', 'MODIFY'], true)) {
            return $result;
        }
        if ($decision === 'BLOCK') {
            throw new RuntimeException('GlobiGuard blocked the governed action.');
        }
        if ($decision === 'QUEUE') {
            throw new RuntimeException('GlobiGuard queued the governed action for review; do not perform the downstream business action yet.');
        }
        throw new RuntimeException('GlobiGuard returned an unsupported decision; do not perform the downstream business action.');
    }

    public function authorizeAction(array $body): array
    {
        $this->requireWrite('Action authorization');
        return $this->transport->request('POST', '/v1/actions/authorize', $body);
    }

    public function requestApproval(array $body): array
    {
        $this->requireWrite('Approval creation');
        return $this->transport->request('POST', '/v1/actions/approvals', $body);
    }

    public function getApprovalStatus(string $approvalId): array
    {
        return $this->transport->request('GET', '/v1/actions/approvals/' . rawurlencode($approvalId));
    }

    public function getEvidenceReferences(
        ?string $authorizationId = null,
        ?string $approvalId = null,
        ?string $workflowRunId = null
    ): array {
        return $this->transport->request(
            'GET',
            '/v1/actions/evidence',
            query: [
                'authorizationId' => $authorizationId,
                'approvalId' => $approvalId,
                'workflowRunId' => $workflowRunId,
            ]
        );
    }

    public function exportEvidencePackage(array $body = []): array
    {
        $this->requireWrite('Evidence export');
        return $this->transport->request('POST', '/v1/audit/export', $body);
    }

    public function getEvidencePackageSummary(string $evidencePackageId): array
    {
        return $this->transport->request(
            'GET',
            '/v1/audit/evidence-packages/' . rawurlencode($evidencePackageId) . '/summary'
        );
    }

    public function getIncidentReplay(string $lookupKind, string $lookupId): array
    {
        $allowed = ['workflowRunId', 'correlationId', 'queueEntryId', 'auditEventId', 'authorizationId'];
        if (!in_array($lookupKind, $allowed, true)) {
            throw new RuntimeException('Unsupported incident replay lookup kind.');
        }
        return $this->transport->request(
            'GET',
            '/v1/audit/incident-replay',
            query: [$lookupKind => $lookupId]
        );
    }

    public function reviewQueue(string $queueEntryId, string $action, array $body = []): array
    {
        $this->requireWrite('Queue review');
        if (!in_array($action, ['approve', 'reject', 'modify', 'escalate', 'resume'], true)) {
            throw new RuntimeException('Unsupported queue review action.');
        }
        return $this->transport->request(
            'POST',
            '/v1/queue/' . rawurlencode($queueEntryId) . '/' . $action,
            $body
        );
    }

    private function requireWrite(string $operation): void
    {
        if ($this->readOnly) {
            throw new RuntimeException($operation . ' requires a server client.');
        }
    }

    public function waitForApproval(
        string $queueEntryId,
        int $maxAttempts = 60,
        int $intervalMilliseconds = 1000
    ): array {
        if ($maxAttempts < 1) {
            throw new RuntimeException('maxAttempts must be at least 1.');
        }
        for ($attempt = 1; $attempt <= $maxAttempts; $attempt++) {
            $entry = $this->transport->request(
                'GET',
                '/v1/queue/' . rawurlencode($queueEntryId)
            );
            $status = $entry['status'] ?? null;
            if (in_array($status, ['APPROVED', 'AUTO_APPROVED', 'RESUMED'], true)) {
                return $entry;
            }
            if (in_array($status, ['REJECTED', 'EXPIRED', 'FAILED'], true)) {
                throw new RuntimeException("Queued action resolved as {$status}; do not perform the downstream business action.");
            }
            if ($status === 'MODIFIED') {
                throw new RuntimeException('The reviewer approved a modified action summary. Rebuild the real payload and request a new authorization before executing it.');
            }
            if (!in_array($status, ['PENDING', 'ESCALATED'], true)) {
                throw new RuntimeException('GlobiGuard returned an unsupported approval state; the downstream business action remains stopped.');
            }
            if ($attempt < $maxAttempts) {
                usleep(max(0, $intervalMilliseconds) * 1000);
            }
        }
        throw new RuntimeException('Queued action is still pending; do not perform the downstream business action yet.');
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
            'packageName' => $packageName,
            'packageVersion' => $packageVersion,
            'integrationKind' => $integrationKind,
            'runtimeKind' => $runtimeKind,
            'environment' => $profile['environment'],
            'deploymentMode' => $profile['deploymentMode'],
            'issuerMode' => $profile['issuerMode'],
            'installReporting' => $profile['installReporting'],
            'installLabel' => $profile['installLabel'] ?? null,
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
    private const MANIFEST_TYPE = 'globiguard.entitlement.v1';

    /** @param array<string,string> $publicKeysById base64url Ed25519 public keys keyed by kid */
    public static function verifySignedManifest(
        string $compactJws,
        array $publicKeysById,
        array $options = [],
    ): array
    {
        $parts = explode('.', $compactJws);
        if (count($parts) !== 3) {
            throw new RuntimeException('Entitlement manifest must be compact JWS.');
        }
        $header = self::decodeObject($parts[0], 'protected header');
        if (($header['alg'] ?? null) !== 'EdDSA' || ($header['typ'] ?? null) !== self::MANIFEST_TYPE) {
            throw new RuntimeException('Unsupported entitlement manifest protected header.');
        }
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '' || !isset($publicKeysById[$kid])) {
            throw new RuntimeException('Unknown entitlement signing key.');
        }
        $signature = self::base64UrlDecode($parts[2]);
        $publicKey = self::base64UrlDecode($publicKeysById[$kid]);
        $signingInput = $parts[0] . '.' . $parts[1];
        if (!sodium_crypto_sign_verify_detached($signature, $signingInput, $publicKey)) {
            throw new RuntimeException('Invalid entitlement manifest signature.');
        }
        $payload = self::decodeObject($parts[1], 'payload');
        self::validatePayload($payload);

        $issuedAt = self::timestamp($payload, 'issuedAt');
        $notBefore = self::timestamp($payload, 'notBefore');
        $expiresAt = self::timestamp($payload, 'expiresAt');
        $now = self::optionTimestamp($options['now'] ?? null);
        if ($issuedAt > $expiresAt || $notBefore >= $expiresAt) {
            throw new RuntimeException('Entitlement manifest timestamps are inconsistent.');
        }
        if ($notBefore > $now) {
            throw new RuntimeException('Entitlement manifest is not active yet.');
        }
        if ($expiresAt <= $now) {
            throw new RuntimeException('Entitlement manifest is expired.');
        }

        $subject = $payload['subject'];
        self::expect($options['expectedIssuer'] ?? null, $payload['issuer'], 'issuer');
        self::expect($options['expectedOrgId'] ?? null, $subject['orgId'], 'organization');
        self::expect($options['expectedProjectId'] ?? null, $subject['projectId'], 'project');
        self::expect($options['expectedEnvironment'] ?? null, $subject['environment'], 'environment');
        self::expect($options['expectedDeploymentMode'] ?? null, $subject['deploymentMode'], 'deployment mode');
        return $payload;
    }

    private static function validatePayload(array $payload): void
    {
        if (($payload['manifestType'] ?? null) !== self::MANIFEST_TYPE || ($payload['manifestVersion'] ?? null) !== 1) {
            throw new RuntimeException('Unsupported entitlement manifest payload.');
        }
        foreach (['manifestId', 'issuer', 'issuedAt', 'notBefore', 'expiresAt'] as $field) {
            self::requiredString($payload, $field);
        }
        $subject = self::requiredArray($payload, 'subject');
        foreach (['orgId', 'workspaceName', 'orgSlug', 'projectId', 'projectSlug'] as $field) {
            self::requiredString($subject, $field);
        }
        if (!in_array(self::requiredString($subject, 'environment'), ['sandbox', 'live'], true)) {
            throw new RuntimeException('Entitlement manifest subject environment is invalid.');
        }
        if (!in_array(self::requiredString($subject, 'deploymentMode'), ['self_hosted', 'sovereign'], true)) {
            throw new RuntimeException('Entitlement manifest subject deployment mode is invalid.');
        }

        $commercial = self::requiredArray($payload, 'commercial');
        if (!in_array(self::requiredString($commercial, 'commercialPlan'), ['FREE', 'STARTER', 'GROWTH', 'SCALE', 'ENTERPRISE'], true)) {
            throw new RuntimeException('Entitlement manifest commercial plan is invalid.');
        }
        if (!in_array(self::requiredString($commercial, 'billingStatus'), ['FREE', 'PILOT', 'ACTIVE', 'GRACE', 'PAST_DUE', 'SUSPENDED', 'CANCELED'], true)) {
            throw new RuntimeException('Entitlement manifest billing status is invalid.');
        }
        if (!array_key_exists('pilotActive', $commercial) || !is_bool($commercial['pilotActive'])) {
            throw new RuntimeException('Entitlement manifest pilotActive must be boolean.');
        }

        $entitlements = self::requiredArray($payload, 'entitlements');
        self::nullableCounter($entitlements, 'includedQueriesPerMonth');
        self::nullableCounter($entitlements, 'frameworkSlots');
        if (!in_array(self::requiredString($entitlements, 'overageMode'), ['NONE', 'METERED', 'CONTRACT'], true)) {
            throw new RuntimeException('Entitlement manifest overage mode is invalid.');
        }
    }

    private static function decodeObject(string $encoded, string $label): array
    {
        try {
            $value = json_decode(self::base64UrlDecode($encoded), true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable $error) {
            throw new RuntimeException('Invalid entitlement manifest ' . $label . '.', 0, $error);
        }
        if (!is_array($value)) {
            throw new RuntimeException('Entitlement manifest ' . $label . ' must be a JSON object.');
        }
        return $value;
    }

    private static function requiredArray(array $parent, string $field): array
    {
        $value = $parent[$field] ?? null;
        if (!is_array($value)) {
            throw new RuntimeException('Entitlement manifest field ' . $field . ' must be an object.');
        }
        return $value;
    }

    private static function requiredString(array $parent, string $field): string
    {
        $value = $parent[$field] ?? null;
        if (!is_string($value) || trim($value) === '') {
            throw new RuntimeException('Entitlement manifest field ' . $field . ' must be a non-empty string.');
        }
        return $value;
    }

    private static function timestamp(array $parent, string $field): \DateTimeImmutable
    {
        try {
            return new \DateTimeImmutable(self::requiredString($parent, $field));
        } catch (\Throwable $error) {
            throw new RuntimeException('Entitlement manifest field ' . $field . ' must be an ISO timestamp.', 0, $error);
        }
    }

    private static function optionTimestamp(mixed $value): \DateTimeImmutable
    {
        if ($value instanceof \DateTimeInterface) {
            return \DateTimeImmutable::createFromInterface($value);
        }
        if ($value === null) {
            return new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        }
        if (!is_string($value)) {
            throw new RuntimeException('Entitlement verification now must be an ISO timestamp or DateTimeInterface.');
        }
        try {
            return new \DateTimeImmutable($value);
        } catch (\Throwable $error) {
            throw new RuntimeException('Entitlement verification now must be an ISO timestamp.', 0, $error);
        }
    }

    private static function nullableCounter(array $parent, string $field): void
    {
        if (!array_key_exists($field, $parent)) {
            throw new RuntimeException('Entitlement manifest field ' . $field . ' is required.');
        }
        $value = $parent[$field];
        if ($value !== null && (!is_int($value) || $value < 0)) {
            throw new RuntimeException('Entitlement manifest field ' . $field . ' must be null or a non-negative integer.');
        }
    }

    private static function expect(mixed $expected, mixed $actual, string $label): void
    {
        if ($expected === null) {
            return;
        }
        if (!is_string($expected) || !is_string($actual) || !hash_equals($expected, $actual)) {
            throw new RuntimeException('Entitlement manifest ' . $label . ' does not match the expected value.');
        }
    }

    private static function base64UrlDecode(string $value): string
    {
        return base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true) ?: throw new RuntimeException('Invalid base64url value.');
    }
}

