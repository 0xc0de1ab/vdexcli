# vdexcli 로드맵

현재 상태를 기준으로 한 향후 확장 계획. 우선순위 기준: 사용자 영향(H), 구현 복잡도(L/M/H), 선행 조건.

## 현재 상태 (v0.2.1)

### 가능한 것

- VDEX v027 파일의 모든 바이트 파싱 (헤더, 4개 섹션, 바이트 커버리지)
- 내장 DEX 파일 추출
- verifier-deps 섹션 수정 (replace/merge 모드)
- 7개 출력 포맷 (text/json/jsonl/summary/sections/coverage/table)
- ANSI 색상 지원 (`--color auto|always|never`, 터미널 자동 감지)
- 구조화된 진단 시스템 (33개 진단 코드, 패키지별 에러 컨텍스트)
- 98개 테스트 (e2e 32 + parser 51 + extractor 9 + integration 3 + subtests)
- GitHub Actions CI (lint/test/build 5 platform), Release (tag → 바이너리), Integration Tests

### 알려진 제약

| 제약 | 설명 |
|------|------|
| verifier 섹션만 수정 가능 | checksum, DEX, type-lookup 섹션은 읽기 전용 |
| 패치 payload 크기 제한 | 새 payload가 기존 섹션 크기를 초과하면 실패 (파일 재배치 미지원) |
| VDEX v027만 지원 | v021~v026 이하 / v028 이상 미파싱 |
| DM 포맷 verifier 파싱 한계 | DEX 섹션 없는 VDEX에서 class_def_count를 추론 불가 → verifier 상세 파싱 불가 |
| modifier/dex/presenter/binutil 패키지 테스트 없음 | parser(88.9%)와 extractor만 단위 테스트 보유 |
| modifier에 인터페이스 없음 | mock 불가, 순수 함수 호출 기반 |

### 이미 완료된 항목 (로드맵 원안 대비)

| 원안 위치 | 항목 | 완료 커밋 |
|-----------|------|----------|
| Phase 4.3 | GitHub Actions CI/Release/Integration | `cbc1de5` |
| (미계획) | `--format table` + ANSI `--color` | `5b3e5aa` |
| (미계획) | 에러 메시지 컨텍스트 개선 (dex/modifier/parser) | `f17e537` |
| (미계획) | e2e subprocess 테스트 33개 | `f219a37` |
| (미계획) | 아키텍처 문서 (Mermaid 다이어그램) | `3800d1d` |

---

## Phase 1 — 안정성 및 테스트 강화

현재 아키텍처 안에서 품질을 높이는 작업. 외부 인터페이스 변경 없음.

### 1.1 테스트 커버리지 확대

| 패키지 | 현재 | 목표 | 작업 |
|--------|------|------|------|
| internal/parser | 88.9% | 95%+ | 남은 엣지 케이스 보강 |
| internal/modifier | 0% | 80%+ | BuildVerifierSection*, CompareVerifierSectionDiff 단위 테스트 |
| internal/dex | 0% | 80%+ | Parse, ParseStrings, ParseClassDefs 단위 테스트 |
| internal/presenter | 0% | 70%+ | 각 Write* 함수 출력 검증 |
| internal/binutil | 0% | 90%+ | ReadULEB128 엣지 케이스, overflow, boundary |

- 복잡도: **L**
- 선행조건: 없음

### 1.2 modifier 패키지 분할

현재 721줄 단일 파일 → 4파일 분리:

```
internal/modifier/
├── patch.go      ParseVerifierPatch, ValidateIndices
├── builder.go    BuildVerifierSection{Replacement,Merge}, BuildVerifierDexBlock
├── compare.go    CompareVerifierSectionDiff, VerifierSectionClassEqual
└── writer.go     WriteOutputFileAtomic, AppendModifyLog
```

- 복잡도: **L**
- 선행조건: 없음

### 1.3 modifier/presenter 인터페이스 정의

```go
// internal/modifier
type VerifierBuilder interface {
    BuildReplacement(dexes []model.DexReport, checksums []uint32, patch model.VerifierPatchSpec) ([]byte, []string, error)
    BuildMerge(dexes []model.DexReport, checksums []uint32, section model.VdexSection, raw []byte, patch model.VerifierPatchSpec) ([]byte, []string, error)
}

// internal/presenter
type ReportWriter interface {
    Write(w io.Writer, report *model.VdexReport) error
}
```

- 복잡도: **M**
- 선행조건: 1.2 (modifier 분할 후 인터페이스 추출이 자연스러움)

### 1.4 flagsbinder 마이그레이션

`cmd/` 플래그를 `github.com/dh-kam/refutils/flagsbinder`로 교체:
- 전역 변수 제거 → opts struct + `binder.BindCommand`
- `PreRunE`에서 바인딩, `RunE`에서 비즈니스 로직 위임
- 테스트 시 상태 오염 완전 제거

- 복잡도: **M**
- 선행조건: 없음

---

## Phase 2 — 수정 기능 확장

verifier-deps 수정의 실용성을 높이는 기능.

### 2.1 DM 포맷 verifier 파싱 개선

DEX 섹션 없는 VDEX에서 class_def_count를 verifier 섹션 내부 구조에서 역추론:
- per-dex offset 간 간격으로 class offset 테이블 크기 추정
- `(blockSize - extraStringsSize) / 4 - 1 = class_def_count` 휴리스틱

- 복잡도: **M**
- 선행조건: 1.1 (166개 실제 DM VDEX로 검증)

### 2.2 섹션 크기 자동 확장 (파일 재배치)

현재 새 verifier payload가 기존 섹션보다 크면 에러. 이를 해결하려면:
1. 새 payload 크기에 맞춰 파일 재배치 (section offset 조정)
2. 후속 섹션(type-lookup 등) offset을 이동
3. 전체 파일을 재조립

```
AS-IS: payload > section.Size → error
TO-BE: payload > section.Size → 자동 재배치 + type-lookup offset 조정
```

- 복잡도: **H**
- 선행조건: 1.1 (수정 후 round-trip 검증에 테스트 필수)
- 위험: offset 오류 시 ART 런타임 crash

### 2.3 checksum 자동 갱신

DEX checksum을 재계산하여 kChecksumSection 갱신. 현재는 수동으로 맞춰야 함.

- 복잡도: **M**
- 선행조건: 2.2

### 2.4 type-lookup 테이블 재생성

verifier 수정 후 class 구성이 바뀌면 type-lookup 해시 테이블도 재계산해야 함. ART의 `TypeLookupTable::Create()` 로직을 Go로 포팅:
1. 각 class descriptor의 modified UTF-8 해시 계산
2. 2-phase insertion (직접 + 충돌 체인)
3. 결과를 kTypeLookupTableSection에 기록

- 복잡도: **H**
- 선행조건: 2.2 (섹션 크기 조정 필요)
- 참조: `art-reference/type_lookup_table.cc`

---

## Phase 3 — 멀티 버전 지원

### 3.1 VDEX v021~v026 파싱

v027 이전 버전의 헤더/섹션 레이아웃이 다름 (섹션 테이블 미존재, 고정 레이아웃).
- version dispatch를 `ParseVdex()` 진입부에서 분기
- `internal/parser/` 내에 버전별 파서 함수 추가
- model 타입은 공유 (출력 형식은 동일하게 유지)

- 복잡도: **H**
- 참조: `art-reference/vdex_file.h`의 버전 히스토리

### 3.2 VDEX v028+ 호환

ART `main` 브랜치에서 v028이 도입될 경우:
- 새 섹션 kind 자동 감지 (unknown으로 표시)
- 새 verifier 인코딩 변경 시 builder 확장

- 복잡도: 변경 규모에 따라 **M~H**

---

## Phase 4 — 도구 생태계

### 4.1 VDEX diff 커맨드

두 VDEX 파일의 구조적 차이를 비교:

```bash
vdexcli diff before.vdex after.vdex --format json
```

섹션별 크기 변화, verifier class 변경 목록, type-lookup 엔트리 차이.

- 복잡도: **M**
- 선행조건: 없음 (기존 parser 활용)

### 4.2 VDEX 생성 (from scratch)

DEX 파일 목록 → 새 VDEX 생성:

```bash
vdexcli create --dex classes.dex --dex classes2.dex -o app.vdex
```

1. DEX 파일 파싱
2. checksum 계산
3. verifier-deps 초기화 (모든 class unverified)
4. type-lookup 테이블 생성
5. VDEX 조립 + 기록

- 복잡도: **H**
- 선행조건: 2.2, 2.3, 2.4

---

## 우선순위 요약

```
v0.3: Phase 1 (안정성)
  1.1 테스트 커버리지
  1.2 modifier 분할
  1.3 인터페이스
  1.4 flagsbinder

v0.4: Phase 2 (수정 확장)
  2.1 DM 파싱 → 2.2 섹션 재배치 → 2.3 checksum → 2.4 type-lookup

v0.5: Phase 3 (멀티 버전)
  3.1 v021~v026 → 3.2 v028+

v1.0: Phase 4 (생태계)
  4.1 diff → 4.2 create
```

## 기여

이슈나 PR은 [GitHub](https://github.com/0xc0de1ab/vdexcli)에서 환영합니다.
로드맵 항목은 GitHub Issues로 추적할 예정입니다.
