# CI/CD Workflows

## 개요

```
push(main) / workflow_dispatch → [01] CI Build (ci.yml)
v*.*.* 태그 / workflow_dispatch → Release (release.yml)
주간(월) / push(main) / workflow_dispatch → test-integration.yml
```

## [01] CI Build — `ci.yml`

**트리거:**
- `push` → `main` 브랜치 (`.md`, `docs/**`, `LICENSE`, Issue 템플릿 변경 제외)
- `workflow_dispatch` — GitHub UI / API에서 수동 실행 가능
  - 옵션: `skip_cache` (모듈 캐시 무시 여부)

| Job | 역할 |
|-----|------|
| `fmt` | `gofmt -l` — 포맷되지 않은 파일 존재 시 실패 |
| `vet` | `go mod tidy` drift 체크 + `go mod verify` + `go vet ./...` + `GOOS=js GOARCH=wasm go vet ./wasm/` |
| `lint` | `golangci-lint` (staticcheck, errcheck 포함) |
| `vulncheck` | `govulncheck` — 알려진 CVE 스캔 |
| `test` | `go test -v -count=1 ./...` + 커버리지 ≥ 85% 검증 + `coverage.out` 아티팩트 업로드 |
| `build` | 5 플랫폼 매트릭스 (linux/darwin/windows × amd64/arm64) + linux/amd64 스모크 테스트 |
| `build-wasm` | `GOOS=js GOARCH=wasm` 빌드 — `vdex.wasm` 아티팩트 업로드 |

**커버리지 대상 패키지:**
- `internal/{binutil,parser,modifier,extractor,model,presenter}`
- `pkg/vdex/`

**경로 제외 (paths-ignore):**
`*.md`, `docs/**`, `LICENSE`, `.github/ISSUE_TEMPLATE/**`

**동시 실행 제한:** 같은 `ref`에 대해 이전 실행 자동 취소 (`cancel-in-progress: true`)

---

## Release — `release.yml`

**트리거:** `v[0-9]+.[0-9]+.[0-9]+` 태그 push, `workflow_dispatch`

| Job | 역할 |
|-----|------|
| `test` | 릴리즈 전 전체 테스트 |
| `release` | 5 플랫폼 빌드 + tar.gz/zip 패키징 |
| `publish` | SHA256 체크섬 생성 + GitHub Release 생성 |

릴리즈 노트: `.github/release.yml` 카테고리 자동 분류 (7개 섹션).

---

## test-integration.yml

**트리거:** 주간(월 00:00 UTC), `push` to main, `workflow_dispatch`

실제 Android 16 VDEX 파일 166개로 전체 파서 통합 테스트.

---

## 설정 파일

| 파일 | 역할 |
|------|------|
| `.github/release.yml` | 릴리즈 노트 카테고리 (Breaking/Features/Fixes/Performance/Docs/Deps/Other) |
| `.github/dependabot.yml` | Go 모듈 + GitHub Actions 주간 업데이트 |
| `.github/CODEOWNERS` | 코드 소유자 |
| `.github/ISSUE_TEMPLATE/` | 버그 리포트 + 기능 요청 템플릿 |
