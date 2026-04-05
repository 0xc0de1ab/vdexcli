# Branch Protection Rules

## main 브랜치 보호 설정

GitHub UI: **Settings → Branches → Add rule → Branch name pattern: `main`**

### 필수 설정

| 설정 | 값 | 이유 |
|------|---|------|
| Require a pull request before merging | On | 직접 push 방지 |
| Require approvals | 1 | 코드 리뷰 필수 |
| Require status checks to pass | On | CI 통과 필수 |
| Required checks | `test`, `lint` | 핵심 검증 job |
| Require branches to be up to date | On | 최신 main 기준 검증 |

### 선택 설정

| 설정 | 값 | 비고 |
|------|---|------|
| Require conversation resolution | On | PR 코멘트 해결 필수 |
| Do not allow bypassing | Off | 관리자 긴급 머지 허용 |
| Allow force pushes | Off | 히스토리 보호 |
| Allow deletions | Off | 브랜치 삭제 방지 |

### CLI 설정 (gh auth login 필요)

```bash
gh api repos/0xc0de1ab/vdexcli/branches/main/protection -X PUT -f \
  required_status_checks='{"strict":true,"contexts":["test","lint"]}' \
  required_pull_request_reviews='{"required_approving_review_count":1}' \
  enforce_admins=false \
  restrictions=null
```
