# vdexcli

[![CI](https://github.com/0xc0de1ab/vdexcli/actions/workflows/ci.yml/badge.svg)](https://github.com/0xc0de1ab/vdexcli/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/0xc0de1ab/vdexcli)](https://github.com/0xc0de1ab/vdexcli/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/0xc0de1ab/vdexcli)](https://goreportcard.com/report/github.com/0xc0de1ab/vdexcli)
[![Go Reference](https://pkg.go.dev/badge/github.com/0xc0de1ab/vdexcli/pkg/vdex.svg)](https://pkg.go.dev/github.com/0xc0de1ab/vdexcli/pkg/vdex)

**Android VDEX 파일의 모든 바이트를 분석합니다.**
CLI, Go 라이브러리, 또는 브라우저(WebAssembly)를 통해 파싱·설명·추출·비교·패치를 수행합니다.

English documentation: [README.md](README.md)

```
$ vdexcli explain app.vdex

offset     size  type        path                                value
---------- ----- ----------- ----------------------------------- ---------------------------
0x00000000     4  magic       vdex.header.magic                  "vdex"
0x00000004     4  bytes       vdex.header.version                "027\0"
0x00000008     4  uint32_le   vdex.header.num_sections           4
0x0000000c    12  bytes       vdex.section[0].header             kind=0 off=0x3c size=4
...
coverage: 204/204 bytes (100.0%) — all bytes explained
```

---

## 목차

- [VDEX란?](#vdex란)
- [기능 요약](#기능-요약)
- [빠른 시작](#빠른-시작)
- [CLI 사용법](#cli-사용법)
  - [parse](#parse)
  - [explain](#explain)
  - [extract-dex](#extract-dex)
  - [modify](#modify)
  - [diff](#diff)
  - [dump](#dump)
- [Go 라이브러리 API](#go-라이브러리-api)
- [WebAssembly 엔진](#webassembly-엔진)
- [브라우저 데모](#브라우저-데모)
- [설치](#설치)
- [프로젝트 구조](#프로젝트-구조)
- [CI / 워크플로](#ci--워크플로)
- [테스트](#테스트)
- [VDEX v027 포맷 참조](#vdex-v027-포맷-참조)
- [기여](#기여)

---

## VDEX란?

**VDEX** (**V**erified **DEX**)는 Android ART 런타임이 `dexpreopt` 과정에서 생성하는 바이너리 컨테이너입니다. 하나 이상의 DEX 파일을 다음 데이터와 함께 묶습니다:

- **Verifier dependency data** — ART가 어떤 클래스를 어떤 타입 계층 기준으로 검증했는지 기록
- **Checksum table** — 포함된 각 DEX에 대한 CRC32 체크섬
- **Type lookup table** — 클래스 디스크립터 빠른 검색용 해시 테이블

VDEX 파일은 디바이스의 `/data/dalvik-cache/` 또는 `.dm` 형식 파일 내부에 존재합니다. 이 구조를 이해하는 것은 다음 작업에 필수적입니다:

- AOSP 빌드에서 `dexpreopt` 결과물 감사
- ART 검증 동작 연구
- 커스텀 클래스 로더 툴링 개발

---

## 기능 요약

| 분류 | 기능 |
|------|------|
| **CLI** | `parse`, `explain`, `extract-dex`, `modify`, `diff`, `dump` |
| **출력 포맷** | `text`, `json`, `jsonl`, `summary`, `sections`, `coverage`, `table` |
| **바이트 단위 분석** | 모든 바이트를 이름·타입·설명이 붙은 필드로 매핑 |
| **DEX 테이블 분해** | `string_ids`, `type_ids`, `proto_ids`, `field_ids`, `method_ids`, `class_defs` 개별 분해 |
| **Go 라이브러리** | `pkg/vdex` — import 가능한 공개 API (`ExplainBytes`, `ParseBytes`, ...) |
| **WebAssembly** | `wasm/` — 표준 Go 툴체인으로 브라우저 실행 |
| **브라우저 데모** | 드래그앤드롭 VDEX 분석기 (`demo/index.html`) |
| **AOSP 호환** | ART 런타임 인코딩과 일치하는 섹션-절대 오프셋 |
| **진단 코드** | 34개의 에러/경고 코드 + 조치 가능한 힌트 |
| **엄격 모드** | 패턴 필터링된 경고를 CI 게이트에서 치명적 오류로 처리 |
| **Verifier 패치** | JSON으로 verifier-deps 섹션 교체 또는 병합 |
| **DEX 추출** | 커스텀 파일명 템플릿으로 임베디드 DEX 추출 |
| **비교(Diff)** | 구조적 비교; exit 0 = 동일, 1 = 다름 |

---

## 빠른 시작

```bash
# 설치
go install github.com/0xc0de1ab/vdexcli@latest

# 파싱 — 전체 구조 출력
vdexcli parse app.vdex

# 설명 — 바이트 단위 필드 맵
vdexcli explain app.vdex

# 특정 바이트 오프셋 조회
vdexcli explain --offset 0x3c app.vdex

# 임베디드 DEX 파일 추출
vdexcli extract-dex app.vdex ./dex-out/

# 두 빌드 비교
vdexcli diff before.vdex after.vdex

# Verifier 의존성 패치
vdexcli modify --verifier-json patch.json in.vdex out.vdex
```

---

## CLI 사용법

### parse

VDEX 전체 구조를 파싱하여 선택한 포맷으로 출력합니다.

```bash
vdexcli parse app.vdex                              # 사람이 읽기 쉬운 텍스트 (기본값)
vdexcli parse --json app.vdex                       # 예쁜 형식의 JSON
vdexcli parse --format jsonl app.vdex               # 한 줄 JSON (로그 파이프라인용)
vdexcli parse --format summary app.vdex             # CI용 한 줄 key=value
vdexcli parse --format sections app.vdex            # TSV 섹션 테이블
vdexcli parse --format coverage app.vdex            # 바이트 커버리지만
vdexcli parse --format table --color never app.vdex # 정렬된 테이블
vdexcli parse --strict --strict-warn "re:(checksum|version)" app.vdex
```

**출력 예시 (텍스트):**

```
file: app.vdex
size: 204 bytes
vdex magic="vdex" version="027" sections=4
sections:
  kind=kChecksumSection      (0) off=0x3c  size=0x4
  kind=kDexFileSection       (1) off=0x40  size=0x70
  kind=kVerifierDepsSection  (2) off=0xb0  size=0x1c
  kind=kTypeLookupTableSection (3) off=0xcc size=0x0
checksums: 1
  [0]=0xcafebabe
dex files: 1
  [0] off=0x40 size=0x70 magic="dex\n" ver="035" file_size=112
       strings=0 types=0 protos=0 fields=0 methods=0 class_defs=3
verifier_deps: off=0xb0 size=0x1c
  [dex 0] verified=2 unverified=1 pairs=1 extra_strings=0
byte_coverage: 204/204 bytes (100.0%)
```

**배치 파이프라인:**

```bash
for f in *.vdex; do vdexcli parse --format summary "$f"; done
# status=ok file=base.vdex size=524288 version=027 coverage=100.0% gaps=0
```

---

### explain

VDEX 파일의 **모든 바이트**를 이름·타입·설명이 붙은 프리미티브 필드로 매핑합니다.
패딩과 갭을 포함하여 모든 바이트가 설명됩니다.

```bash
vdexcli explain app.vdex                    # 헥스 덤프 테이블 (텍스트)
vdexcli explain --format json app.vdex      # 전체 PrimitiveMap JSON
vdexcli explain --offset 0x3c app.vdex      # 특정 바이트 오프셋의 필드
vdexcli explain --offset 60 app.vdex        # 10진수 오프셋도 지원
vdexcli explain --offset 0x3c --json app.vdex  # 단일 필드 JSON
```

**DEX 테이블 분해** — VDEX에 임베디드된 각 DEX는 구성 테이블 단위로 분해됩니다:

```
vdex.dex[0].string_ids[0].offset     → uint32_le  0x00000070
vdex.dex[0].type_ids[0]              → uint32_le  0x00000005
vdex.dex[0].proto_ids[0].shorty_idx  → uint32_le  0x00000001
vdex.dex[0].field_ids[0].class_idx   → uint16_le  0x0000
...
```

---

### extract-dex

VDEX 컨테이너에서 임베디드 DEX 파일을 모두 추출합니다.

```bash
vdexcli extract-dex app.vdex ./dex-out/
vdexcli extract-dex --json app.vdex ./out/
vdexcli extract-dex --extract-name-template "{base}_{index}_{checksum_hex}.dex" app.vdex ./out/
vdexcli extract-dex --extract-continue-on-error app.vdex ./out/
```

템플릿 토큰: `{base}`, `{index}`, `{checksum}`, `{checksum_hex}`, `{offset}`, `{size}`

---

### modify

JSON 디스크립터를 통해 verifier-deps 섹션을 패치합니다.

```bash
# Replace 모드 (기본값) — 전체 verifier 섹션 재빌드
vdexcli modify --verifier-json patch.json in.vdex out.vdex

# Merge 모드 — 기존 데이터 위에 오버레이
vdexcli modify --mode merge --verifier-json patch.json in.vdex out.vdex

# Dry run — 파일 쓰지 않고 패치 검증만
vdexcli modify --dry-run --json --verifier-json patch.json in.vdex out.vdex

# stdin에서 패치 읽기
cat patch.json | vdexcli modify --verifier-json - in.vdex out.vdex
```

**패치 JSON 스키마:**

```json
{
  "mode": "replace",
  "dexes": [{
    "dex_index": 0,
    "extra_strings": ["Ljava/lang/Object;"],
    "classes": [
      {"class_index": 0, "verified": true,  "pairs": [{"dest": 5, "src": 10}]},
      {"class_index": 1, "verified": false}
    ]
  }]
}
```

예제 패치 파일: [`samples/`](samples/)

---

### diff

두 VDEX 파일을 구조적으로 비교합니다. 종료 코드: `0` = 동일, `1` = 다름.

```bash
vdexcli diff before.vdex after.vdex           # 색상 포함 텍스트
vdexcli diff --json before.vdex after.vdex    # JSON 비교 결과
vdexcli diff --format summary a.vdex b.vdex   # CI용 한 줄 요약
```

**출력 예시:**

```
VDEX diff
  A: before.vdex (204 bytes)
  B: after.vdex  (204 bytes)

verifier_deps: (2 classes changed)
  [dex 0] verified 2→0 (-2)  pairs 1→0 (-1)  extras 0→0

summary: sections=0 checksums=0 dexes=0 verifier=2 typelookup=0
```

---

### dump

바이너리에 내장된 필드 의미 사전을 출력합니다.

```bash
vdexcli dump                      # YAML 형식
vdexcli dump --format jsonl       # JSON (파이프라인용)
```

---

## 전역 플래그

| 플래그 | 설명 |
|--------|------|
| `-i, --in <path>` | 입력 VDEX 경로 (위치 인자 대신 사용 가능) |
| `--format <mode>` | `text` \| `json` \| `jsonl` \| `summary` \| `sections` \| `coverage` \| `table` |
| `--json` | `--format json` 단축키 |
| `--color <mode>` | `auto` (기본값) \| `always` \| `never` |
| `--strict` | 매칭된 경고를 치명적 오류로 처리 (비정상 종료) |
| `--strict-warn <patterns>` | 쉼표로 구분된 필터; `re:` 접두사로 정규표현식 사용 |
| `--show-meaning` | 필드 설명 포함 (기본값: `true`) |
| `--extract-dex <dir>` | 파싱 중 DEX 파일 추출 |
| `--extract-name-template` | 파일명 템플릿 (기본값: `{base}_{index}_{checksum}.dex`) |
| `--extract-continue-on-error` | 오류 발생 시 계속 추출 |
| `-v, --version` | 버전 출력 후 종료 |

---

## Go 라이브러리 API

`vdexcli`는 다른 Go 프로젝트에서 직접 import할 수 있는 안정된 공개 API를 [`pkg/vdex`](pkg/vdex/)에 제공합니다.

```go
import "github.com/0xc0de1ab/vdexcli/pkg/vdex"
```

### 핵심 함수

```go
// 바이트 단위 어노테이션 필드 맵 — 모든 바이트가 설명됩니다.
// WASM 호환 (파일시스템 접근 없음).
fm, err := vdex.ExplainBytes(data []byte) (*vdex.FieldMap, error)

// 고수준 구조적 리포트.
// WASM 호환.
report, err := vdex.ParseBytes(data []byte, opts ...vdex.Option) (*vdex.Report, error)

// 비-WASM (데스크톱/서버) 빌드용 편의 래퍼.
fm, err     := vdex.ExplainFile(path string) (*vdex.FieldMap, error)
report, err := vdex.ParseFile(path string, opts ...vdex.Option) (*vdex.Report, error)
```

### 옵션

```go
vdex.WithMeanings()   // 사람이 읽을 수 있는 필드 설명 포함
vdex.WithDexPreview() // 리포트에 DEX 클래스 미리보기 포함
```

### 주요 타입

```go
// Field — 단일 어노테이션 바이트 범위.
type Field struct {
    Offset      uint32
    Size        uint32
    Type        FieldType     // "uint32_le", "magic", "bytes", "padding", ...
    RawBytes    []byte
    ParsedValue interface{}
    LogicalPath string        // 예: "vdex.dex[0].string_ids[3].offset"
    Summary     string
    Description string
}

// FieldMap — VDEX 파일의 완전한 어노테이션 뷰.
type FieldMap struct {
    Fields       []*Field
    TotalBytes   uint32
    UnmappedGaps []ByteRange
}

// Report — 고수준 파싱 결과.
type Report struct {
    File         string
    Header       *VdexHeader
    Sections     []SectionHeader
    Checksums    []uint32
    DexFiles     []DexInfo
    VerifierDeps *VerifierDepsInfo
    TypeLookup   *TypeLookupInfo
    Coverage     *CoverageReport
    Diagnostics  []Diagnostic
}
```

### 사용 예시

```go
package main

import (
    "fmt"
    "os"

    "github.com/0xc0de1ab/vdexcli/pkg/vdex"
)

func main() {
    data, _ := os.ReadFile("app.vdex")

    // 바이트 단위 분석
    fm, err := vdex.ExplainBytes(data)
    if err != nil {
        panic(err)
    }
    fmt.Printf("총 바이트: %d, 필드 수: %d\n", fm.TotalBytes, len(fm.Fields))
    for _, f := range fm.Fields[:5] {
        fmt.Printf("0x%08x  %-12s  %s\n", f.Offset, f.Type, f.LogicalPath)
    }

    // 고수준 파싱
    report, _ := vdex.ParseBytes(data, vdex.WithMeanings())
    fmt.Printf("VDEX 버전: %d, DEX 수: %d\n",
        report.Header.Version, report.Header.DexCount)
}
```

---

## WebAssembly 엔진

`wasm/` 패키지는 표준 Go 툴체인(`GOOS=js GOARCH=wasm`)을 사용하여 전체 엔진을 WebAssembly로 컴파일합니다. TinyGo나 코드 생성 해킹 없이 제네릭 등 모든 Go 기능을 그대로 사용할 수 있습니다.

### 빌드

```bash
GOOS=js GOARCH=wasm go build \
  -trimpath -ldflags="-s -w" \
  -o vdex.wasm ./wasm/

# 또는 Makefile 사용:
make demo
```

출력: `vdex.wasm` (스트립 후 ~3.3 MB)

### JavaScript API

```js
// 런타임 + WASM 로드
const go = new Go();  // wasm_exec.js에서 제공
const result = await WebAssembly.instantiateStreaming(fetch("vdex.wasm"), go.importObject);
go.run(result.instance);

// VDEX 파일 분석 (FileReader → Uint8Array → WASM)
const bytes = new Uint8Array(await file.arrayBuffer());

// 바이트 단위 필드 맵 → { fields: [...], total_bytes: N, unmapped_gaps: [...] }
const fieldMap = window.vdex.explain(bytes);

// 고수준 구조적 리포트 → { header: {...}, dex_files: [...], ... }
const report = window.vdex.parse(bytes);

// 엔진 버전 문자열
console.log(window.vdex.version);  // "v0.1.0"
```

### WASM 브리지 함수

| 함수 | 입력 | 출력 |
|------|------|------|
| `window.vdex.explain(Uint8Array)` | VDEX 원시 바이트 | `{ fields, total_bytes, unmapped_gaps }` 또는 `{ error }` |
| `window.vdex.parse(Uint8Array)` | VDEX 원시 바이트 | `VdexReport` 객체 또는 `{ error }` |
| `window.vdex.version` | — | 버전 문자열 |

두 함수 모두 **동기(synchronous)** 방식 — JS 측에서 `async/await` 불필요.

---

## 브라우저 데모

`demo/`에는 완전한 클라이언트 사이드 VDEX 분석기가 포함되어 있습니다. 서버 불필요 — 엔진이 WebAssembly를 통해 브라우저 내에서 완전히 실행됩니다.

### 로컬 실행

```bash
# 1. WASM 바이너리 빌드 및 wasm_exec.js 복사
make demo
# 또는: bash demo/build_demo.sh

# 2. 정적 파일 서버 실행 (어떤 서버도 가능)
make demo-serve
# → http://localhost:8080

# 수동 방법:
cd demo && python3 -m http.server 8080
```

### 기능

- **드래그앤드롭** 또는 **파일 선택기**로 `.vdex` 파일 로드
- **Explain 탭** — 완전한 바이트 단위 필드 테이블:
  - 오프셋, 크기, 타입 배지, 논리 경로, 디코딩된 값, 헥스 미리보기
  - 경로 접두사 및 필드 타입으로 필터링
  - 패딩 토글, JSON 복사 버튼
  - 행 클릭 시 전체 헥스 덤프가 포함된 상세 모달
- **Parse 탭** — 고수준 구조 요약 카드 (헤더, 섹션, DEX 파일, verifier deps, 커버리지)
- **커버리지 바** — 애니메이션 바이트 커버리지 표시기
- **100% 클라이언트 사이드** — 파일 업로드 없음, 분석 없음, 외부 의존성 없음

> **참고:** 브라우저는 WASM에 적절한 HTTP 서버(`Content-Type: application/wasm`)가 필요합니다. `file://`로 `index.html`을 직접 열면 동작하지 않습니다.

---

## 진단 코드

모든 경고와 오류는 `severity`, `code`, `message`, `hint`가 포함된 구조적 진단 정보를 제공합니다.

**텍스트 출력:**

```
section warnings (1):
  ! section kDexFileSection has zero size
    ~ this section is empty; normal for DM-format VDEX (no embedded DEX)
verifier warnings (1):
  ! dex 0: inferred class_def_count=246 from verifier section (DM format)
    ~ no embedded DEX; class count inferred from offset table heuristic
```

**JSON 출력:**

```json
{
  "severity": "warning",
  "category": "section",
  "code": "WARN_SECTION_ZERO_SIZE",
  "message": "section kDexFileSection has zero size",
  "hint": "this section is empty; normal for DM-format VDEX (no embedded DEX)"
}
```

**34개의 진단 코드**가 다음을 포함합니다: 잘린 파일, 잘못된 매직, 손상된 섹션, 깨진 LEB128, 레거시 버전 가드, 타입 룩업 실패 등.

**CI 통합:**

```bash
# 체크섬/verifier 문제에서만 실패; 구조적 경고는 무시
vdexcli parse --strict --strict-warn "re:(checksum|verifier)" app.vdex

# JSON 출력에서 모든 에러 추출
vdexcli parse --json app.vdex | jq '[.diagnostics[] | select(.severity == 0)]'

# 배치 스캔
for f in *.vdex; do
  errs=$(vdexcli parse --json "$f" | jq '[.diagnostics[] | select(.severity==0)] | length')
  [ "$errs" -gt 0 ] && echo "FAIL $f ($errs errors)"
done
```

---

## 설치

### `go install` 사용 (권장)

```bash
go install github.com/0xc0de1ab/vdexcli@latest
```

### 소스에서 빌드

```bash
git clone https://github.com/0xc0de1ab/vdexcli.git
cd vdexcli
make build          # → build/<os>-<arch>/release/vdexcli
```

사용 가능한 Make 타겟:

| 타겟 | 설명 |
|------|------|
| `make all` | fmt + vet + lint + test + build |
| `make build` | 현재 OS/아키텍처용 릴리즈 바이너리 |
| `make test` | 전체 테스트 스위트 실행 |
| `make lint` | golangci-lint |
| `make fmt` | gofmt 인플레이스 적용 |
| `make vet` | go vet + mod tidy 검사 |
| `make demo` | WASM 데모 아티팩트 빌드 |
| `make demo-serve` | 데모 빌드 후 `localhost:8080`에서 서비스 |
| `make clean` | 빌드 아티팩트 삭제 |

### 사전 빌드 바이너리

[GitHub Releases](https://github.com/0xc0de1ab/vdexcli/releases/latest)에서 다운로드:

```bash
# 체크섬 검증
sha256sum -c vdexcli-checksums.txt
```

지원 플랫폼: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`

### 디버그 빌드

```bash
make build VARIANT=debug
```

---

## 프로젝트 구조

```
vdexcli/
├── main.go                          # 진입점 (7줄)
├── Makefile                         # 빌드, 테스트, 데모 타겟
├── cmd/                             # Cobra CLI 커맨드
│   ├── root.go                      # 루트 커맨드 + 전역 플래그
│   ├── parse.go                     # parse 서브커맨드
│   ├── explain.go                   # explain 서브커맨드
│   ├── extract.go                   # extract-dex 서브커맨드
│   ├── modify.go                    # modify 서브커맨드
│   ├── diff.go                      # diff 서브커맨드
│   ├── dump.go                      # dump 서브커맨드
│   └── version.go                   # version 서브커맨드
├── pkg/
│   └── vdex/                        # ★ 공개 Go 라이브러리 API
│       ├── api.go                   # ExplainBytes, ParseBytes
│       ├── api_fs.go                # ExplainFile, ParseFile (비-WASM)
│       ├── types.go                 # Field, FieldMap, Report, ...
│       ├── options.go               # WithMeanings, WithDexPreview
│       └── doc.go                   # 패키지 문서
├── wasm/
│   └── main.go                      # ★ WebAssembly 진입점 (syscall/js)
├── demo/                            # ★ 브라우저 기반 VDEX 분석기
│   ├── index.html                   # 단일 페이지 앱
│   ├── style.css                    # 다크 글라스모피즘 UI
│   ├── script.js                    # FileReader → WASM 브리지 + 렌더러
│   └── build_demo.sh                # WASM 빌드 + wasm_exec.js 복사
├── internal/
│   ├── binutil/                     # 저수준 바이너리 I/O (ReadU32, LEB128, ...)
│   ├── model/                       # 공유 타입, 상수, 진단 코드
│   ├── dex/                         # DEX 포맷 파싱 (VDEX 독립)
│   ├── parser/                      # VDEX 컨테이너 파싱
│   │   ├── explain.go               # ExplainVdexBytes — 바이트 단위 필드 맵
│   │   ├── explain_dex.go           # DEX 테이블 분해
│   │   ├── parser.go                # ParseVdexBytes — 구조적 리포트
│   │   ├── verifier.go              # VerifierDeps 파싱
│   │   ├── typelookup.go            # TypeLookup 테이블 파싱
│   │   └── legacy.go                # 레거시 VDEX v021-v026 지원
│   ├── modifier/                    # Verifier 섹션 빌드/패치/비교
│   ├── extractor/                   # DEX 파일 추출
│   └── presenter/                   # 출력 포맷팅 + ANSI 색상
│       ├── color_terminal.go        # 터미널 색상 지원 (!js 빌드)
│       └── color_wasm.go            # WASM 빌드용 no-op 오버라이드
├── .github/
│   └── workflows/
│       ├── ci.yml                   # [01] CI Build (7개 job)
│       ├── release.yml              # 릴리즈 파이프라인
│       └── test-integration.yml     # 166개 파일 VDEX 통합 테스트
├── docs/
│   ├── architecture.md              # 패키지 다이어그램 + 설계 결정
│   └── vdex-format.md              # VDEX v027 바이너리 포맷 레퍼런스
├── samples/                         # 예제 verifier 패치 JSON 파일
├── testdata/                        # 통합 테스트용 실제 VDEX 파일
└── ROADMAP.md                       # 단계별 확장 계획
```

---

## CI / 워크플로

### `[01] CI Build` — `ci.yml`

트리거: **`main` 브랜치 push** 및 **수동 실행** (`workflow_dispatch`).

| Job | 검사 내용 |
|-----|-----------|
| `fmt` | `gofmt` 포맷팅 |
| `vet` | `go mod tidy` drift · `go mod verify` · `go vet ./...` · `GOOS=js GOARCH=wasm go vet ./wasm/` |
| `lint` | `golangci-lint` (staticcheck, errcheck 포함) |
| `vulncheck` | `govulncheck` — CVE 스캔 |
| `test` | `go test -v -count=1 ./...` · `pkg/vdex/` 포함 커버리지 ≥ 85% |
| `build` | 5 플랫폼 매트릭스 (linux/darwin/windows × amd64/arm64) + linux/amd64 스모크 테스트 |
| `build-wasm` | `GOOS=js GOARCH=wasm` 빌드 · `vdex.wasm` 아티팩트 업로드 |

**수동 실행 방법:** GitHub → Actions → `[01] CI Build` → **Run workflow** 클릭

### `Release` — `release.yml`

트리거: `v*.*.*` 버전 태그 또는 `workflow_dispatch`.
결과물: 플랫폼별 아카이브 + SHA256 체크섬 + GitHub Release 생성.

### `test-integration.yml`

트리거: 주간(월요일 00:00 UTC), main push, `workflow_dispatch`.
실행: **Android 16 VDEX 파일 166개**를 전체 파서 파이프라인으로 처리.

---

## 테스트

```bash
go test -v ./...
# 또는
make test
```

| 패키지 | 테스트 수 | 비고 |
|--------|-----------|------|
| `cmd` | 35 | 모든 커맨드와 포맷에 대한 E2E 서브프로세스 테스트 |
| `internal/binutil` | 18 | LEB128, 정렬, 인코딩 라운드트립 (100% 커버리지) |
| `internal/parser` | 51+ | 헤더, 섹션, verifier, typelookup, 바이트 단위 explain |
| `internal/modifier` | 30 | 패치 파싱/검증/빌드, 원자적 쓰기 |
| `internal/extractor` | 9 | 목 파일시스템, 인터페이스 검증 |
| `pkg/vdex` | 14 | 공개 API 안정성, 옵션 검증, 타입 별칭 |
| **통합 테스트** | 166 | 실제 Android 16 VDEX 파일 (`android-16.0.0_r4`) |

**커버리지 기준:** 테스트 가능 패키지 전체에서 ≥ 85% (CI에서 강제).

---

## VDEX v027 포맷 참조

AOSP ART [`runtime/vdex_file.h`](https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/vdex_file.h) 기반:

```
오프셋    크기   필드
------   ----   -----
0x00       4    magic        "vdex"
0x04       4    version      "027\0"
0x08       4    num_sections (= 4)
0x0c    N×12    VdexSectionHeader[N]
                  ├ kind    uint32  (0=Checksum, 1=Dex, 2=VerifierDeps, 3=TypeLookup)
                  ├ offset  uint32  섹션 시작 (절대 오프셋)
                  └ size    uint32  섹션 길이 (바이트)

Section 0  kChecksumSection         uint32[D] — 임베디드 DEX별 CRC32
Section 1  kDexFileSection          연결된 DEX 페이로드 (DM 포맷에서는 비어있음)
Section 2  kVerifierDepsSection     DEX별 검증 의존성 데이터
Section 3  kTypeLookupTableSection  DEX별 클래스 디스크립터 해시 테이블
```

전체 필드 단위 레퍼런스: [`docs/vdex-format.md`](docs/vdex-format.md)

---

## 성능

단일 코어 (arm64), 단일 VDEX 파일 기준:

| 파일 크기 | 파싱 시간 | 처리량 |
|-----------|-----------|--------|
| 204 B | ~4 ms | 즉각적 |
| 5.6 KB | ~4 ms | 즉각적 |
| 178 KB (DEX 28개) | ~13 ms | ~14 MB/s |

배치: **166개 파일을 1.4초** 처리 (DM 포맷 클래스 추론 포함).

---

## 기여

- [버그 리포트](https://github.com/0xc0de1ab/vdexcli/issues/new?template=bug_report.md)
- [기능 요청](https://github.com/0xc0de1ab/vdexcli/issues/new?template=feature_request.md)
- [토론](https://github.com/0xc0de1ab/vdexcli/discussions)
