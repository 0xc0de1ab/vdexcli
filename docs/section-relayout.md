# 섹션 재배치 알고리즘 설계

## 문제

현재 `vdexcli modify`는 새 verifier payload가 기존 섹션보다 크면 실패합니다:

```
verifier payload too large: 47 bytes > section size 28
```

이를 해결하려면 파일 전체를 재조립하여 후속 섹션의 offset을 이동해야 합니다.

## VDEX 파일 메모리 레이아웃

ART `WriteToDisk` (`vdex_file.cc:256-367`) 기준:

```
Offset  Content                         Size
------  ------------------------------  ------------------
0x00    VdexFileHeader                  12 bytes (fixed)
0x0C    VdexSectionHeader[4]            48 bytes (fixed)
0x3C    kChecksumSection data           D * 4 bytes
        kDexFileSection data            (0 for DM format)
        [4-byte alignment padding]
        kVerifierDepsSection data       variable
        [4-byte alignment padding]
        kTypeLookupTableSection data    variable
```

**핵심 제약**: 섹션은 순차 배치. verifier 섹션이 커지면 type-lookup 시작 offset이 밀려야 함.

## 재배치 알고리즘

### 입력

```
raw[]byte           원본 VDEX 파일 전체
sections[4]         원본 섹션 헤더
targetKind          수정 대상 섹션 (kVerifierDepsSection = 2)
newPayload[]byte    새 섹션 데이터
```

### 알고리즘

```
func RelayoutVdex(raw []byte, sections []VdexSection, targetKind uint32, newPayload []byte) []byte

1. 섹션을 offset 기준으로 정렬 → ordered[]
   (일반적으로: checksum → dex → verifier → typelookup)

2. 새 파일 버퍼 할당:
   out = []byte{}

3. 고정 헤더 복사 (60 bytes):
   out = append(out, raw[0:60]...)   // header + section headers (placeholder)

4. 각 섹션을 순서대로 재배치:
   for each section in ordered:
     if section.Kind == targetKind:
       data = newPayload
     else:
       data = raw[section.Offset : section.Offset + section.Size]

     // 4-byte 정렬
     while len(out) % 4 != 0:
       out = append(out, 0)

     // 새 offset 기록
     newSections[section.Kind].Offset = len(out)
     newSections[section.Kind].Size = len(data)

     // 데이터 복사
     out = append(out, data...)

5. 섹션 헤더 테이블 업데이트:
   for i, s in newSections:
     binary.LittleEndian.PutUint32(out[12 + i*12 + 0:], s.Kind)
     binary.LittleEndian.PutUint32(out[12 + i*12 + 4:], s.Offset)
     binary.LittleEndian.PutUint32(out[12 + i*12 + 8:], s.Size)

6. return out
```

### 시각화: verifier 확장 시

```
BEFORE (28 bytes verifier):
┌──────┬──────────┬──────┬────────┬────────────┬─────────────┐
│Header│SectHdrs  │ Chk  │  DEX   │ Verifier   │ TypeLookup  │
│ 12B  │  48B     │ 4B   │ 112B   │ 28B        │ 2052B       │
└──────┴──────────┴──────┴────────┴────────────┴─────────────┘
 0x00   0x0C       0x3C   0x40     0xB0         0xCC

AFTER (100 bytes verifier):
┌──────┬──────────┬──────┬────────┬────────────────────┬─────────────┐
│Header│SectHdrs  │ Chk  │  DEX   │ Verifier (expanded)│ TypeLookup  │
│ 12B  │  48B     │ 4B   │ 112B   │ 100B               │ 2052B       │
└──────┴──────────┴──────┴────────┴────────────────────┴─────────────┘
 0x00   0x0C       0x3C   0x40     0xB0                  0x114
                                                          ↑ shifted +72
```

**섹션 헤더만 업데이트, 내부 데이터의 offset은 변경 불필요** (verifier/typelookup의 내부 offset은 섹션 시작 기준 상대값).

## 엣지 케이스

| 케이스 | 처리 |
|--------|------|
| 새 payload < 기존 크기 | 현재와 동일 (0 패딩). 재배치 시 축소도 가능. |
| kDexFileSection size=0 (DM) | 건너뜀 (offset=0, size=0 유지) |
| 정렬 패딩 | 각 섹션 앞에 `Align4(len(out))` |
| 원본에 gap/padding 존재 | 재배치 시 gap 제거됨 (더 작은 파일 가능) |
| 섹션 순서가 비표준 | offset 기준 정렬로 안전 |

## 검증 전략

1. **round-trip 테스트**: 원본 → 재배치 → parse → 원본 parse 결과와 비교
2. **byte coverage**: 재배치된 파일도 100% coverage
3. **diff 검증**: `vdexcli diff original.vdex relayouted.vdex` → verifier만 변경
4. **ART 호환성**: 재배치된 VDEX를 `dex2oat --verify` 또는 에뮬레이터에서 검증

## 구현 위치

```
internal/modifier/relayout.go

func RelayoutVdex(raw []byte, sections []model.VdexSection,
    targetKind uint32, newPayload []byte) ([]byte, error)
```

cmd/modify.go의 현재 에러:
```go
if len(newPayload) > int(section.Size) {
    return fmt.Errorf("verifier payload too large: ...")
}
```

→ 변경:
```go
if len(newPayload) > int(section.Size) {
    raw = modifier.RelayoutVdex(raw, report.Sections, model.SectionVerifierDeps, newPayload)
    // section offsets are now updated in raw
}
```

## 위험 요소

| 위험 | 완화 |
|------|------|
| offset 계산 오류 → ART crash | round-trip 테스트 + byte coverage 100% 검증 |
| 4-byte 정렬 누락 | `binutil.Align4` 일관 사용 |
| verifier 내부 offset 영향 | 내부 offset은 section-absolute → 섹션 시작이 바뀌어도 무관 |
| DM 포맷 호환 | dex section size=0 처리 |

## 선행조건

- modifier 테스트 80%+ (완료: 81.0%)
- parser round-trip 테스트 (완료: e2e `TestE2E_Modify_ReparseOutput`)
- diff 커맨드 (완료: 재배치 전후 비교 가능)
