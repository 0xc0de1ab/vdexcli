# CI Secrets 관리 가이드

## 현재 사용 중인 시크릿

| 시크릿 | 용도 | 설정 방법 |
|--------|------|----------|
| `GITHUB_TOKEN` | GitHub Release 생성, artifact 업로드 | 자동 제공 (설정 불필요) |
| `CODECOV_TOKEN` | 커버리지 리포트 업로드 (선택) | Settings → Secrets → New |

## 시크릿 등록

```
GitHub repo → Settings → Secrets and variables → Actions → New repository secret
```

## 워크플로우에서 참조

```yaml
- uses: codecov/codecov-action@v4
  with:
    token: ${{ secrets.CODECOV_TOKEN }}
    files: coverage.out
```

## 보안 모범 사례

- 시크릿은 로그에 자동 마스킹됨 (`***`)
- `GITHUB_TOKEN` 권한 최소화: ci.yml `contents: read`, release.yml `contents: write`
- 시크릿을 환경변수로 노출할 때 `env:` 블록 사용, `run:` 내 직접 삽입 금지
- Fork PR에서는 시크릿 접근 불가 (보안 기본값)
- 주기적으로 사용하지 않는 시크릿 삭제
