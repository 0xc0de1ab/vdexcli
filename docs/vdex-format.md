# vdex 파일 형식 요약

이 문서는 `vdexcli` 파서를 기준으로 Android ART vdex (`*.vdex`)의 구조와 각 필드의 의미를 정리한 것입니다.

- 대상 버전: ART VDEX `027` (커맨드에서 감지된 버전 문자열)
- 분석 기준: `vdexcli`의 파싱 루틴 및 필드 추론 범위

## 참고한 AOSP 버전 / URL 기록

- 기준 AOSP: `android/platform/art` `main`
- 기준 커밋: `6484611fd45e69db9f33f98bfd6864014b030ecf`  
  - 커밋 시간: `2025-03-25 22:11:44 +0000`
  - 커밋 메타데이터 JSON: https://android.googlesource.com/platform/art/+/refs/heads/main?format=JSON
- 참조 파일(동일 커밋):
  - `runtime/vdex_file.h`  
    https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/runtime/vdex_file.h
  - `runtime/vdex_file.cc`  
    https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/runtime/vdex_file.cc
  - 전체 ART 브랜치 뷰(해당 커밋)  
    https://android.googlesource.com/platform/art/+/6484611fd45e69db9f33f98bfd6864014b030ecf/

## 1. VDEX 헤더

`vdex` 파일 시작부에서 12바이트를 읽습니다.

| 오프셋 | 크기 | 필드 | 의미 |
|---:|---:|---|---|
| `0x00` | 4 | `magic` | `vdex` 고정 문자열 |
| `0x04` | 4 | `version` | 버전 문자열 (`027`, 4바이트) |
| `0x08` | 4 | `number_of_sections` | 섹션 테이블 엔트리 수 |

### 파서 동작
- `magic`이 `vdex`가 아니면 오류 기록
- 버전이 `027`이 아니면 경고 기록
- 헤더 길이(`12 + number_of_sections * 12`)가 파일 크기보다 크면 파싱 실패

## 2. 섹션 헤더 테이블

섹션 헤더는 `number_of_sections` 개수만큼 12바이트씩 존재합니다.

| 오프셋 (entry 기준) | 크기 | 필드 | 의미 |
|---:|---:|---|---|
| `+0x00` | 4 | `kind` | 섹션 종류 |
| `+0x04` | 4 | `offset` | 파일 내 오프셋 |
| `+0x08` | 4 | `size` | 섹션 크기 |

`kind` 매핑(현재 파서가 인식)

- `0x00` (`kChecksumSection`)
- `0x01` (`kDexFileSection`)
- `0x02` (`kVerifierDepsSection`)
- `0x03` (`kTypeLookupTableSection`)
- 그 외 값은 `unknown(x)`로 표시

파서는 섹션 테이블에 대해 추가 유효성 검증을 수행합니다.
- 각 섹션 `offset + size`가 파일 크기를 넘으면 경고
- 길이가 0인 섹션은 경고
- 서로 다른 섹션의 바이트 구간이 겹치면 경고
- 동일 `kind` 섹션이 중복되면 경고를 남기고 `kind` 별로 첫 번째 항목만 사용합니다.

## 3. Kind별 파싱 규칙

`vdexcli`는 아래 순서로 파싱합니다.

- `kChecksumSection`: `uint32` 배열
- `kDexFileSection`: 내장 DEX 목록 파싱
- `kVerifierDepsSection`: 검증 의존성/assignability 정보
- `kTypeLookupTableSection`: 클래스 디스크립터 조회 테이블

### 3.1 `kChecksumSection`

- `size`는 4의 배수여야 함 (아니면 경고)
- 각 값은 각 DEX의 checksum

### 3.2 `kDexFileSection`

- 오프셋/크기 범위가 유효하면 내부를 순회하며 DEX 헤더(`0x70`) 단위로 반복 파싱
- `file_size`가 `kDexFileSection` 범위를 넘으면 해당 dex 크기를 섹션 끝으로 클램프해 추출/표시
- 각 DEX 항목:
  - `magic` (`dex\n`), `version`
  - `checksum_field` (adler32), `signature` (SHA-1, 20바이트)
  - `file_size` / `header_size` / `endian`
  - `link_size` / `link_offset` / `map_offset`
  - `string_ids_size` + `string_ids_off`, `type_ids_size` + `type_ids_off`
  - `proto_ids_size` + `proto_ids_off`, `field_ids_size` + `field_ids_off`
  - `method_ids_size` + `method_ids_off`, `class_defs_size` + `class_defs_off`
  - `data_size`, `data_offset`
  - 클래스 미리보기: `class_defs`를 최대 20개 디스크립터로 출력
- DEX 파싱은 다음 보조 테이블을 사용:
  - `string_ids` → 오프셋 테이블에서 각 문자열의 시작 오프셋 참조
  - `type_ids` → `string_ids` 인덱스로 descriptor 문자열 조회
  - `class_defs` → 각 클래스의 `class_idx`를 `type_ids`를 통해 descriptor로 변환
- `class_defs_size` 개수와 실제 출력 미리보기 개수는 다를 수 있음(미리보기는 상한 20개)

#### DEX 문자열

- 문자열 엔트리는 modified UTF-8 기반
- 파서: `string_id`의 오프셋에서 modified UTF-8 길이 바이트(`uleb128`) + 데이터(널 종료)로 해석

### 3.3 `kVerifierDepsSection`

구조를 대략적으로는 다음처럼 해석합니다.

1. section 시작에서 dex 개수(D)만큼 `uint32[D]` 인덱스 테이블을 읽음 (각 값은 **section-absolute 오프셋** — section 시작 기준)
2. 각 dex별로 해당 오프셋의 블록으로 이동
3. 블록 내부 처리
   - 첫 부분: `class_def_count + 1`개 `uint32` offset 배열 (값은 **section-absolute 오프셋**)
     - 각 클래스 인덱스별 assignability set 시작 오프셋
     - class의 marker가 `0xFFFFFFFF`이면 `not verified`
     - 마지막 엔트리는 assignability 데이터 끝을 가리키는 sentinel
   - 각 클래스 블록은 `[destination(uleb128), source(uleb128)]` 쌍 목록 (pair count prefix 없음, 다음 offset까지가 범위)
   - 4바이트 정렬 패딩 후 추가 문자열: `uint32` 개수 + `uint32[]` 오프셋 배열 (section-absolute) + null-terminated 문자열 데이터
   - 문자열 인덱스는 DEX string table 기반 id와 extra strings 테이블을 합쳐 name 해석
- 파서의 요약 출력
  - `verified_classes`
  - `unverified_classes`
  - `assignability_pairs`
  - `extra_string_count`
  - `first_pairs`(최대 20개 미리보기)

### 3.4 `kTypeLookupTableSection`

각 dex별로 section에서 길이(`uint32`)가 앞에서 먼저 주어지고, 그 길이만큼의 payload를 읽습니다.

- 각 payload는 8바이트 엔트리 여러 개로 이루어진 해시 테이블 뷰로 파싱
  - `offset`(4): 문자열 오프셋
  - `packed`(4): 비트필드
- 비트 해석(ART `libdexfile/dex/type_lookup_table.h`의 `Entry` 클래스와 일치)
  - `class_defs_size == 0`이면 제한적 디코드
  - `maskBits = minimumBitsToStore(class_defs_size - 1)`
  - `class_idx = (packed >> maskBits) & mask`
  - `next_delta = packed & mask`
  - `hash_bits = packed >> (2 * maskBits)`
- 파서가 산출하는 요약
  - `bucket_count`, `entry_count`, `non_empty_buckets`
  - 체인 통계: `max_chain_len`, `avg_chain_len`
  - `sample_entries`(최대 24개 미리보기)

## 4. `vdexcli` 출력 JSON 맵핑

`show-meaning`이 `true`면 JSON 루트에 `meanings`가 포함됩니다.

- `schema_version`: CLI 출력 스키마(`1.0.0`)
- `header`: vdex 헤더
- `sections`: 섹션 kind/offset/size/meaning
- `checksums`: `kChecksumSection` 값
- `dex_files`: 파싱된 DEX 목록
- `verifier_deps`, `type_lookup`: 선택 파트(존재할 때)
- `byte_coverage`: 바이트 단위 파싱 커버리지 (`file_size`, `parsed_bytes`, `unparsed_bytes`, `coverage_percent`, `ranges`, `gaps`)
- `warnings`, `errors`: 파서 수집 메시지
- `warnings_by_category`: 경고 카테고리별 집계(`header|section|checksum|dex|verifier|type_lookup|extract|other`)

`extract-dex` 하위명령에서 `--json`을 사용하면 추출 요약 JSON이 출력됩니다.

- `schema_version`: CLI 출력 스키마 버전
- `file`: 원본 vdex 경로
- `extract_dir`: 출력 폴더
- `name_template`: 적용한 템플릿
- `extracted` / `failed`: 추출 집계
- `warnings`, `warnings_by_category`: 파싱-추출 경고 집계

`modify` 하위명령에서 `--json`을 사용하면 수정 요약 JSON이 출력됩니다.

- `schema_version`: CLI 출력 스키마 버전
- `input_file`: 입력 vdex 경로
- `output_file`: 출력 vdex 경로
- `mode`: 사용된 수정 모드(`replace`/`merge`)
- `status`: 실행 결과 상태 (`ok`, `strict_failed`, `failed`)
- `failure_category`: `strict|parse|compare|write|modify|""`(성공 시 빈 문자열)
- `failure_category_counts`: 실패 카테고리 집계 맵(예: `{"parse":1}`)
- `dry_run`: dry-run 여부
- `patch_dexes`: 패치 항목이 있는 dex 수
- `patch_classes`: 패치된 클래스 총 수
- `patch_extra_strings`: 패치에 포함된 extra string 수
- `total_classes`: 비교 가능한 클래스 항목 총 개수
- `modified_classes`: 기존 verifier 블록 대비 변경된 클래스 수
- `unmodified_classes`: 기존 verifier 블록 대비 변경되지 않은 클래스 수
- `dex_diffs`: dex별 통계 배열 (`dex_index`, `total_classes`, `modified_classes`, `unmodified_classes`, `changed_class_indices`)
- `class_change_percent`: `modified_classes/total_classes * 100`
- `expected_dexes`: 입력에서 추정된 dex 수
- `verifier_section_old_size`: 기존 verifier 섹션 크기
- `verifier_section_new_size`: 재구성 verifier 섹션 크기
- `warnings`, `warnings_by_category`, `errors`: 경고/오류
- `--strict`에서 경고가 매칭되면 `status`가 `strict_failed`가 되며 비정상 종료 코드로 반환됩니다. 이 경우 `modify` 결과는 파일에 기록되지 않습니다.
- `--verify`는 `--dry-run`의 별칭입니다. `--dry-run`/`--verify`는 실제 검증 결과만 계산하고 수정된 파일은 쓰지 않습니다.
- `--quiet` 사용 시 JSON은 동일하며 텍스트 모드의 `modify summary / diff / status / output / result` 라인은 출력되지 않습니다.
- 단, 실패 시에는 `warnings_by_category` 기반 경고 요약이 출력될 수 있습니다.
- `--log-file <path>` 사용 시 JSON 요약을 줄 단위 JSON(`timestamp`, `command`, `args`, `summary`, `modified_dexes`, `top_modified_class_samples`, `modified_class_count`, `strict_matched_warnings`, `failure_reason`, `failure_category`, `failure_category_counts`)으로 누적 기록합니다.
- `failure_reason`은 `strict` 실패 또는 실제 첫 실패 원인을 한 줄 문자열로 정규화해 기록합니다. 출력 파일 쓰기 실패도 동일하게 기록됩니다.
- `failure_category`은 `strict|parse|compare|write|modify` 중 한 종류로 실패 성격을 분류합니다.
- `--verifier-json -`을 사용하면 패치 JSON을 표준입력으로 전달할 수 있습니다.
- `--verify` 사용 시에는 입력 파일과 출력 파일 경로가 같아도 기본 동작으로 허용됩니다. `--force`는 실제 쓰기 모드에서만 필요합니다.
- 출력 파일 기록은 임시 파일에 먼저 쓰고 최종 rename으로 반영해 부분 기록 손상을 방지합니다.

## 5. 주의/한계

- 본 파서는 진단/탐색용 파서로, 일부 malformed 데이터에서 계속 진행해 가능한 부분을 출력합니다.
- ART 변형/버전에 따라 verifier/type-lookup 인코딩이 다를 수 있습니다.
- 경고가 있어도 출력은 계속 되나, 심각한 오류는 구조화된 진단 메시지(`ParseDiagnostic`)로 `errors`에 기록됩니다.
  - 예: `"file too small for VDEX header: 11 bytes (need >= 12)"`, `"invalid VDEX magic: got \"oops\", expected \"vdex\""`
  - 각 진단에는 심각도(`error`/`warning`), 카테고리(`header`/`section`/`checksum`/...), 코드(`ERR_FILE_TOO_SMALL` 등)가 포함됩니다.
- `--strict`와 `--strict-warn`으로 경고 기준 종료를 제어할 수 있습니다.
- 종료 우선순위: `--strict`가 먼저 매칭되고, 그다음 파싱 에러가 반환되므로 strict 매칭이 있으면 우선 strict 에러가 먼저 반영됩니다.
- 텍스트 출력에서는 `warnings_by_category` 개수도 확인할 수 있도록 `카테고리 warnings (건수)` 형식으로 표시됩니다.

## 6. 출력 포맷 (`--format`)

`--format` 플래그로 출력 모드를 제어합니다. `--json`은 `--format json`의 단축입니다.

| 포맷 | 용도 | 설명 |
|------|------|------|
| `text` | 기본값 | 사람이 읽기 쉬운 전체 구조 덤프 |
| `json` | 파이프라인 | pretty-printed JSON (전체 필드) |
| `jsonl` | 로그 수집 | 한 줄 compact JSON (NDJSON) |
| `summary` | CI 게이트 | `status=ok file=... size=... coverage=...` 한 줄 key=value |
| `sections` | grep/awk | 섹션 테이블 TSV (`kind\tname\toffset\tsize`) |
| `coverage` | 커버리지 전용 | 바이트 범위 + gap 목록 |

`--format`이 명시되면 `--json`보다 우선합니다.

### 기타 CLI 토큰

- `--show-meaning`: 텍스트/JSON에 의미 블록 포함
- `--extract-dex`: 파싱 중 dex 추출 실행
- `--extract-name-template`: 추출 파일명 템플릿
- 파일명 충돌 가능성이 있으면 `_N` 접미사를 붙여 중복 파일명을 방지합니다.
- 지원되지 않는 템플릿 토큰은 경고로 기록하고 기본 템플릿으로 폴백됩니다.
- `--extract-continue-on-error`: 추출 실패 시 계속 진행
- `version`, `dump`: 버전/필드 의미만 출력

### 경고 및 strict 필터

- JSON 출력에는 `warnings_by_category`가 추가로 포함되며, 경고가 `header`, `section`, `checksum`, `dex`, `verifier`, `type_lookup`, `extract`, `other`로 분류됩니다.
- `--strict-warn` 필터는 쉼표로 구분된 토큰으로 지정합니다.
  - 기본 동작: 부분 문자열 매칭
  - 정규식 사용: `re:` 접두사를 붙이면 정규식으로 동작합니다.
    - 예) `--strict-warn "re:(checksum|version)|invalid"`
  - 잘못된 정규식은 경고로 기록됩니다.
  - `re:` 표현식이 비어 있거나, 패턴 전체가 무효이면 strict 매칭은 수행되지 않고 경고만 남습니다(매칭 0개).

## 7. 빠른 사용 예시

```bash
# 텍스트 파싱
vdexcli parse samples/app.vdex

# JSON 파싱 + 의미 블록
vdexcli --json --show-meaning parse samples/app.vdex

# 추출 + 템플릿 지정
vdexcli parse --extract-dex ./out --extract-name-template "{base}_{index}_{checksum_hex}_{size}.dex" samples/app.vdex

# strict-warn 예시
vdexcli parse --strict --strict-warn "re:(checksum|version)|invalid" samples/app.vdex
vdexcli parse --strict --strict-warn "re:*" samples/app.vdex  # invalid regex -> warning only

# 엄격 모드로 경고를 에러 처리
vdexcli parse --strict --strict-warn "checksum,version" samples/app.vdex

# 하위 명령 사용
vdexcli extract-dex samples/app.vdex ./out
vdexcli dump
vdexcli version

# verifier section 수정 (replace)
cat > /tmp/patch.json <<'EOF'
{
  "mode": "replace",
  "dexes": [
    {
      "dex_index": 0,
      "classes": [
        {
          "class_index": 3,
          "verified": true,
          "pairs": [
            {
              "dest": 12,
              "src": 13
            }
          ]
        }
      ],
      "extra_strings": [
        "Lcom/example/PatchedType;"
      ]
    }
  ]
}
EOF

vdexcli modify --verifier-json /tmp/patch.json samples/app.vdex samples/app-modified.vdex
# dry-run(실제 출력 파일 미작성)
vdexcli modify --dry-run --json --verifier-json /tmp/patch.json samples/app.vdex /tmp/out.vdex
vdexcli modify --verify --verifier-json /tmp/patch.json samples/app.vdex /tmp/out.vdex
cat /tmp/patch.json | vdexcli modify --verifier-json - samples/app.vdex samples/app-modified.vdex
vdexcli modify --force --verifier-json /tmp/patch.json samples/app.vdex samples/app.vdex
```

동봉 샘플 템플릿(`samples/`)

- `samples/verifier-patch-replace.json`
- `samples/verifier-patch-merge.json`
- `samples/verifier-patch-merge-extras-only.json`

### `modify` 패치 JSON 스키마

- `mode`: `replace | merge` (`merge`는 기존 verifier_deps에 병합)
- `mode`가 없으면 CLI `--mode` 값(`replace`)을 사용
- `dexes`: 변경할 dex 단위 목록
- 동일 `dexes[].dex_index`와 동일 `dexes[].classes[].class_index`는 중복될 수 없습니다.
- `dexes[].dex_index` 및 `class_index`는 0 이상 정수여야 합니다.
- 지원하지 않는 필드가 있으면 파서 오류(`invalid verifier patch json`)로 처리합니다.
- 빈 입력이나 여러 JSON 객체가 포함된 잘못된 JSON은 파서 오류로 처리합니다.
- `dexes[].dex_index`: 0 기반 dex 인덱스
- `dexes[].classes`: 클래스별 덮어쓰기 항목
- `dexes[].classes[].class_index`: 0 기반 class_def 인덱스
- `dexes[].classes[].verified`: 생략 시 `pairs` 존재 여부로 기본값 처리 (`pairs` 비어 있으면 미검증)
- `dexes[].classes[].pairs`: assignability 쌍 배열
- `dexes[].classes[].pairs[].dest`: destination string id
- `dexes[].classes[].pairs[].src`: source string id
- `dexes[].extra_strings`: 해당 dex에서만 사용되는 추가 문자열 목록

`merge` 모드 동작

- 기존 verifier 블록을 먼저 파싱해 클래스별 상태/쌍/문자열 테이블을 읽습니다.
- 동일 dex/class 항목은 `verified`와 `pairs`가 완전히 덮어쓰기됩니다.
- `extra_strings`는 기존 목록 뒤에 추가됩니다.
- 클래스 개수를 알 수 없는 dex에서는 클래스 패치(`classes`)를 적용할 수 없습니다.
- `classes`가 없는 `merge` 패치(예: `samples/verifier-patch-merge-extras-only.json`)는 기존 verifier 블록의 문자열 테이블에만 `extra_strings`를 추가합니다.

예시(merge)

```json
{
  "mode": "merge",
  "dexes": [
    {
      "dex_index": 0,
      "classes": [
        {
          "class_index": 3,
          "verified": false
        }
      ],
      "extra_strings": [
        "Lcom/example/MergedExtra;"
      ]
    }
  ]
}
```

## 8. JSON 출력 예시

### parse JSON(요약)

```bash
vdexcli --json parse samples/app.vdex
```

```json
{
  "schema_version": "1.0.0",
  "file": "javalib.vdex",
  "size": 5608,
  "header": {
    "magic": "vdex",
    "version": "027",
    "number_of_sections": 4
  },
  "sections": [
    {"kind": 0, "offset": 60, "size": 4, "name": "kChecksumSection", "meaning": "..."},
    {"kind": 1, "offset": 0, "size": 0, "name": "kDexFileSection", "meaning": "..."},
    {"kind": 2, "offset": 64, "size": 3491, "name": "kVerifierDepsSection", "meaning": "..."},
    {"kind": 3, "offset": 3556, "size": 2052, "name": "kTypeLookupTableSection", "meaning": "..."}
  ],
  "checksums": [3077383428],
  "dex_files": null,
  "verifier_deps": {"offset": 64, "size": 3491, "dexes": [{"dex_index": 0, "verified_classes": 0, "...": "..."}]},
  "type_lookup": {"offset": 3556, "size": 2052, "dexes": [{"dex_index": 0, "bucket_count": 256, "...": "..."}]},
  "byte_coverage": {
    "file_size": 5608, "parsed_bytes": 5607, "unparsed_bytes": 1,
    "coverage_percent": 99.98,
    "ranges": [{"offset": 0, "size": 12, "label": "vdex_header"}, "..."],
    "gaps": [{"offset": 3555, "size": 1, "label": "gap/padding"}]
  },
  "warnings": ["section kind 1 has zero size", "..."],
  "warnings_by_category": {"section": ["section kind 1 has zero size"]},
  "errors": []
}
```

### extract-dex JSON

```bash
vdexcli extract-dex --json samples/app.vdex ./out
```

```json
{
  "schema_version": "1.0.0",
  "file": "samples/app.vdex",
  "size": 123456,
  "extract_dir": "./out",
  "name_template": "{base}_{index}_{checksum}.dex",
  "extracted": 4,
  "failed": 0,
  "warnings": [
    "section kind 0 has zero size"
  ],
  "warnings_by_category": {
    "section": [
      "section kind 0 has zero size"
    ]
  },
  "errors": []
}
```

### modify `--json` stdout 출력

`--json modify`는 `ModifySummary` 구조를 stdout으로 출력합니다:

```bash
vdexcli --json modify --dry-run --verifier-json patch.json samples/app.vdex /tmp/app.vdex
```

```json
{
  "schema_version": "1.0.0",
  "input_file": "samples/app.vdex",
  "output_file": "/tmp/app.vdex",
  "mode": "replace",
  "status": "ok",
  "dry_run": true,
  "patch_dexes": 1,
  "patch_classes": 2,
  "total_classes": 12,
  "modified_classes": 2,
  "unmodified_classes": 10,
  "class_change_percent": 16.67,
  "dex_diffs": [{"dex_index":0,"total_classes":12,"modified_classes":2,"unmodified_classes":10,"changed_class_indices":[3,5]}],
  "warnings": [],
  "errors": [],
  "failure_category": "",
  "failure_category_counts": {}
}
```

### modify `--log-file` NDJSON 출력

`--log-file`은 실행마다 한 줄 JSON(`ModifyLogEntry`)을 누적합니다. stdout JSON과 필드가 다릅니다:

- `timestamp`, `command`, `args`: 실행 컨텍스트
- `summary`: 위 `ModifySummary` 전체를 포함
- `modified_dexes`, `top_modified_class_samples`, `modified_class_count`: 변경 요약
- `strict_matched_warnings`, `failure_reason`, `failure_category`, `failure_category_counts`: 실패 분류

실패 시 `failure_reason`과 `failure_category`를 먼저 확인하면 원인 추적이 빠릅니다.

실패 분류 예시(한 줄 JSON):

```json
{"timestamp":"2026-03-04T10:15:01Z","command":["vdexcli","modify","--strict","--strict-warn","verifier","--json","--verifier-json","patch.json","samples/app.vdex","/tmp/app.vdex"],"summary":{"schema_version":"1.0.0","input_file":"samples/app.vdex","output_file":"/tmp/app.vdex","mode":"replace","status":"strict_failed","dry_run":false,"patch_dexes":1,"patch_classes":1,"patch_extra_strings":0,"total_classes":12,"modified_classes":0,"unmodified_classes":12,"class_change_percent":0,"expected_dexes":1,"verifier_section_old_size":2048,"verifier_section_new_size":2048,"dex_diffs":[{"dex_index":0,"total_classes":12,"modified_classes":0,"unmodified_classes":12,"changed_class_indices":[]}],"warnings_by_category":{"verifier":["verifier section malformed: duplicate class index entry"]},"warnings":["verifier section malformed: duplicate class index entry"],"errors":[],"failure_category_counts":{"strict":1},"failure_category":"strict","failure_reason":"strict mode: matched 1 warning(s): [\"verifier section malformed: duplicate class index entry\"]"}
{"timestamp":"2026-03-04T10:16:03Z","command":["vdexcli","modify","--json","--verifier-json","patch.json","samples/app.vdex","/tmp/app.vdex"],"summary":{"schema_version":"1.0.0","input_file":"samples/app.vdex","output_file":"/tmp/app.vdex","mode":"replace","status":"failed","dry_run":false,"patch_dexes":1,"patch_classes":1,"patch_extra_strings":0,"total_classes":12,"modified_classes":0,"unmodified_classes":12,"class_change_percent":0,"expected_dexes":1,"verifier_section_old_size":0,"verifier_section_new_size":0,"dex_diffs":[{"dex_index":0,"total_classes":0,"modified_classes":0,"unmodified_classes":0,"changed_class_indices":[]}],"warnings_by_category":{},"warnings":[],"errors":["invalid vdex verifier section: section header offset out of range"],"failure_category_counts":{"parse":1},"failure_category":"parse","failure_reason":"invalid vdex verifier section: section header offset out of range"}
{"timestamp":"2026-03-04T10:17:21Z","command":["vdexcli","modify","--verifier-json","patch.json","samples/app.vdex","/tmp/app.vdex"],"summary":{"schema_version":"1.0.0","input_file":"samples/app.vdex","output_file":"/tmp/app.vdex","mode":"merge","status":"failed","dry_run":false,"patch_dexes":1,"patch_classes":1,"patch_extra_strings":0,"total_classes":12,"modified_classes":0,"unmodified_classes":12,"class_change_percent":0,"expected_dexes":1,"verifier_section_old_size":2048,"verifier_section_new_size":2048,"dex_diffs":[{"dex_index":0,"total_classes":12,"modified_classes":0,"unmodified_classes":12,"changed_class_indices":[]}],"warnings_by_category":{"verifier":["verifier section class diff check failed"]},"warnings":["verifier section class diff check failed"],"errors":["verifier section class diff check failed"],"failure_category_counts":{"compare":1},"failure_category":"compare","failure_reason":"verifier section class diff check failed"}
```

로그 후처리 예시:

```bash
# 실패 항목만 선별
jq -R 'try fromjson catch empty | select(.summary.status != "ok")' /tmp/vdex-modify.log

# failure_category 집계
jq -R 'try fromjson catch empty | .failure_category' /tmp/vdex-modify.log \
  | jq -s 'group_by(.) | map({category: .[0], count: length})'

# write 실패만 추려 파일/오류 출력
jq -R 'try fromjson catch empty | select(.failure_category=="write") | {ts:.timestamp, file:.summary.output_file, reason:.failure_reason}' /tmp/vdex-modify.log

# 또는 제공 스크립트로 바로 집계
./scripts/analyze-modify-log.sh /tmp/vdex-modify.log

# 추가 옵션 예시
./scripts/analyze-modify-log.sh --status failed --last 100 /tmp/vdex-modify.log
./scripts/analyze-modify-log.sh --category write --max-failures 0 /tmp/vdex-modify.log
./scripts/analyze-modify-log.sh --json --status failed /tmp/vdex-modify.log
./scripts/analyze-modify-log.sh --since 2026-03-04T10:00:00Z --until 2026-03-04T11:00:00Z /tmp/vdex-modify.log
```
