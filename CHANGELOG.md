# Changelog

## 0.2.3

- Read HTTP response headers through `http_get_last_response_headers()` on PHP
  8.4 and newer, while retaining the legacy scoped-header fallback for PHP 8.2
  and 8.3.
- Avoided the PHP 8.5 response-header deprecation without changing transport or
  fail-closed status handling.

## 0.2.2

- Corrected the GitHub Actions YAML for authenticated Packagist updates.

## 0.2.1

- Updated the SDK identification header to the published package version.
- Updated Packagist publishing to the current authenticated JSON API.

## 0.2.0

- Tightened governed-action execution so only a current, obligation-free
  `ALLOW` decision is executable.
- Added regression coverage for `MODIFY`, queued approvals, and other
  non-executable decisions.

## 0.1.0

- Initial dependency-minimal PHP SDK foundation.
- Added credential helpers, safe request transport, resource clients, governed action helpers, trust webhook verification, bootstrap helpers, and offline entitlement manifest verification with `ext-sodium`.

