# CI/CD Workflows

## Overview

```
push/PR → ci.yml (lint, vet, vulncheck, fmt, test, build)
v*.*.* tag → release.yml (test → build 5 platforms → checksums → GitHub Release)
weekly/manual → test-integration.yml (166 real VDEX files)
```

## ci.yml

**Trigger:** push to main, pull requests

| Job | Purpose |
|-----|---------|
| lint | golangci-lint (includes staticcheck, errcheck) |
| vet | go mod tidy check + go mod verify + go vet |
| vulncheck | govulncheck for known vulnerabilities |
| fmt-check | gofmt formatting verification |
| test | go test -v + 80% coverage threshold + artifact upload |
| build | 5-platform matrix (linux/darwin/windows x amd64/arm64) + smoke test |

Skips: `*.md`, `docs/**`, `LICENSE`, `.github/ISSUE_TEMPLATE/**`

## release.yml

**Trigger:** tag push matching `v[0-9]+.[0-9]+.[0-9]+`, workflow_dispatch

| Job | Purpose |
|-----|---------|
| test | Full test suite before release |
| release | Matrix build (5 platforms) + tar.gz/zip packaging |
| publish | Download artifacts + SHA256 checksums + GitHub Release |

Release notes auto-categorized by `.github/release.yml` (7 sections).

## test-integration.yml

**Trigger:** weekly (Monday 00:00 UTC), push to main, workflow_dispatch

Runs 166 real Android 16 VDEX files through the full parser.

## Configuration

| File | Purpose |
|------|---------|
| `.github/release.yml` | Release note categories (Breaking/Features/Fixes/Performance/Docs/Deps/Other) |
| `.github/dependabot.yml` | Weekly updates for Go modules + GitHub Actions |
| `.github/ISSUE_TEMPLATE/` | Bug report + feature request templates |
