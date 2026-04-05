# CI Debugging Checklist

## 실패 시 확인 순서

1. **Actions 탭** — 실패한 job/step 이름 확인
2. **로그 확인** — step 클릭 → `go test -v` 출력에서 `FAIL` 검색
3. **로컬 재현** — `make all` (fmt→vet→lint→test→build)
4. **의존성 확인** — `go mod tidy && git diff go.mod go.sum`
5. **재실행** — "Re-run failed jobs" 버튼
6. **디버그 로깅** — "Re-run jobs" → "Enable debug logging" 체크

## 흔한 실패 원인

| 증상 | 원인 | 해결 |
|------|------|------|
| `go mod tidy` diff | 의존성 미커밋 | `go mod tidy` 후 커밋 |
| coverage < 85% | 새 코드 테스트 누락 | 테스트 추가 |
| lint 실패 | 포맷/스타일 위반 | `gofmt -w .` |
| build 실패 | 컴파일 에러 | 로그에서 에러 행 확인 |
