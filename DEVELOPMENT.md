# GlobiGuard PHP SDK - Development Guide

## CI/CD Pipeline Overview

This repository uses GitHub Actions for automated testing, building, and publishing.

### Workflows

#### 1. **Test & Lint** (`test.yml`)
- **Triggers:** Every push to `main`/`develop`, and on all pull requests
- **What it does:**
  - Tests across PHP 8.2, 8.3, and 8.4
  - Validates PHP syntax
  - Runs tests via PHPUnit
- **Status check:** ✅ Must pass before merging to `main`

#### 2. **Build & Package** (`build.yml`)
- **Triggers:** Every push to `main`/`develop`, and on all pull requests
- **What it does:**
  - Validates Composer configuration
  - Creates distribution archives (zip/tar.gz)
  - Uploads to GitHub Artifacts
- **Purpose:** Verify package structure before publish

#### 3. **Publish** (`publish.yml`)
- **Triggers:** When a git tag matching `v*.*.*` is pushed
- **What it does:**
  - Creates GitHub Release
  - Notifies Packagist of new release
- **Usage:**
  ```bash
  git tag v0.1.0
  git push origin v0.1.0
  ```

#### 4. **Security Scan** (`security.yml`)
- **Triggers:** Every push to `main`/`develop`, weekly on Sunday
- **What it does:**
  - Runs security checker
  - Runs Psalm static analysis
  - Validates PHP syntax
- **Purpose:** Continuous security and quality monitoring

### Branch Protection

The `main` branch is protected with:
- ✅ Require 1 pull request review before merging
- ✅ Require all status checks to pass
- ✅ Require branches to be up to date before merging
- ✅ Dismiss stale pull request approvals on new commits
- ✅ Require code owner reviews
- ❌ Force pushes disabled
- ❌ Deletions disabled

### Versioning Strategy

We use **Semantic Versioning** (major.minor.patch) with git tags:

- **v0.1.0** → Initial release
- **v0.1.1** → Patch fix
- **v0.2.0** → Minor feature
- **v1.0.0** → Major release (breaking changes)

Version is managed via git tags; Packagist syncs automatically.

### Publishing Workflow

```bash
# 1. Make changes on a feature branch
git checkout -b feat/new-feature
git commit -m "feat: new feature"
git push origin feat/new-feature

# 2. Create PR, review, merge to main

# 3. Tag release
git tag v0.1.0
git push origin v0.1.0

# 4. Watch CI/CD create release
# Packagist auto-syncs from git tags
# composer require globiguard/globiguard
```

### Development Cycle

1. **Create feature branch:** `git checkout -b feature/name main`
2. **Make changes:** Edit code, test locally
3. **Run tests locally:** `./vendor/bin/phpunit tests/`
4. **Commit:** `git commit -m "feat: description"`
5. **Push:** `git push origin feature/name`
6. **Create PR:** Open GitHub pull request to `main`
7. **Review:** Automated tests and code review
8. **Merge:** Merge PR to `main`
9. **Publish (optional):** Tag release with `git tag v0.X.X`

### Local Testing

```bash
# Install dependencies
composer install

# Validate composer.json
composer validate --strict

# Run tests
./vendor/bin/phpunit tests/

# Or run PHP directly
php -d error_reporting=E_ALL tests/SmokeTest.php

# Lint PHP files
php -l src/Globiguard.php

# Check syntax
composer run-script lint 2>/dev/null || php -l src/
```

### Code Owners

Code ownership is defined in `.github/CODEOWNERS`:
- All files: `@globi-explore/maintainers`
- PRs require approval from code owners before merge

### Repository Configuration

- **Default branch:** `main`
- **Discussions:** Enabled (for Q&A)
- **Releases:** Auto-generated from tags
- **Topics:** `globiguard`, `sdk`, `governance`, `php`, `composer`
- **Visibility:** Public
- **PHP version:** 8.2+
- **Extensions required:** json, sodium

## Troubleshooting

**Composer install fails?**
- Clear cache: `composer clear-cache`
- Update composer: `composer self-update`
- Check PHP version: `php -v`

**Tests fail?**
- Run with verbose output: `./vendor/bin/phpunit -v tests/`
- Check PHP extensions: `php -m`
- Verify json and sodium are installed

**Packagist publish fails?**
- Ensure repository is on Packagist
- Check git tag format: `v0.X.X`
- Wait 5 minutes for Packagist to sync

## Questions?

See main repository README or GitHub Discussions for Q&A.
