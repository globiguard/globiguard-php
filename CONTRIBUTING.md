# Contributing

GlobiGuard PHP SDK changes should avoid Composer runtime dependencies unless a security review accepts a specific exception.

## Validate locally

```bash
composer validate --strict
php -l src/Globiguard.php
php tests/SmokeTest.php
```

Examples must use placeholder secrets only and webhook handlers must pass raw request body bytes into verification.

