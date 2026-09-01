# Track D synthetic name recipe

Full byte-level spec of how the `rstflt.sys` v5.0.0+ Track D
`RegNtPostEnumerateKey` handler rewrites subkey names under
`HKLM\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_*&Prod_*[&Rev_*]`.
Purpose: let a userland tool (validator, hash-oracle, golden-vector
harness) reproduce the kernel's synthetic names byte-for-byte given
the same seed and the same real name.

The referenced primitive `Get-Fnv1a64Hash` in
`scripts/spoof-pci-hardwareid.ps1` supplies the MIXING FUNCTION but
NOT the INPUT CONSTRUCTION described here. A userland reproducer
must build the mixer input per the recipe below, then call
`Get-Fnv1a64Hash` on the resulting byte buffer.

---

## 1. Real-name shape

The kernel only touches subkey names whose leaf part
starts with the exact 9-wchar prefix `L"Disk&Ven_"` (case-insensitive
via `RtlPrefixUnicodeString`). Names not matching this prefix are
passed through untouched.

Recognized fields inside a matching name (all case-insensitive on
the marker; the field VALUE is preserved case as read):

| Field | Marker | Value = wchars between marker end and next `&` (or end-of-string) |
|-------|--------|--------------------------------------------------------------------|
| Ven   | `Disk&Ven_` (starts at wchar index 0)      | begins at wchar index 9 |
| Prod  | `&Prod_`                                    | begins at prod-marker end |
| Rev   | `&Rev_`                                     | begins at rev-marker end  |

Only fields whose marker is present in the real name get rewritten;
missing markers cause the field to stay as-is.

---

## 2. Per-field mixer input

For each field `F` in `{Ven, Prod, Rev}` that is present and has
length `L` (in wchars, `L > 0`), the kernel emits `L` uppercase-hex
wchars by iterating `round = 0, 1, 2, ...` until it has produced `L`
characters (16 hex chars per hash, so
`ceil(L / 16)` rounds are needed).

For each `round`, the mixer input buffer is built by concatenating
these bytes in order, with NO separators between the domain and
seed sections:

```
<domain-cstring-bytes>                              # 9 or 10 bytes, see table
+ <seed-bytes>                                      # up to 64 bytes (see sec 3)
+ '|'                                               # 1 byte, ASCII 0x7C
+ <UTF-16LE bytes of the real field value>         # 2 * L bytes
+ '|'                                               # 1 byte, ASCII 0x7C
+ <round-byte>                                      # 1 byte, see sec 4
```

Total input length varies by field length and seed length; the
kernel caps the buffer at 192 bytes (`buf[192]` local) and silently
truncates anything longer — no field in a real SCSI subkey has ever
come close to this cap, but a userland port must apply the same cap
for exact reproducibility.

### 2.1 Domain-cstring bytes

Exact ASCII bytes, including the trailing `|`, NO trailing NUL:

| Field | Domain string   | Bytes                        | Length |
|-------|-----------------|------------------------------|--------|
| Ven   | `SCSI_VEN\|`    | `53 43 53 49 5F 56 45 4E 7C` | 9      |
| Prod  | `SCSI_PROD\|`   | `53 43 53 49 5F 50 52 4F 44 7C` | 10  |
| Rev   | `SCSI_REV\|`    | `53 43 53 49 5F 52 45 56 7C` | 9      |

### 2.2 Real-field bytes

The kernel copies the field value as-is from the caller's
`KEY_BASIC_INFORMATION` / `KEY_NODE_INFORMATION` Name buffer, which
holds a UTF-16LE `WCHAR[]`. A userland reproducer must feed the
identical UTF-16LE bytes to the mixer — NOT the UTF-8 encoding of
the same characters. Concretely: real value `IntelSSD` is
16 mixer bytes (`49 00 6E 00 74 00 65 00 6C 00 53 00 53 00 44 00`),
not 8.

### 2.3 Round-byte semantics

`round-byte = (UCHAR)('0' + (round & 0xF))`. This means:

| round | round-byte |
|-------|-----------|
| 0     | `'0'` = 0x30 |
| 1     | `'1'` = 0x31 |
| ...   | ...       |
| 9     | `'9'` = 0x39 |
| 10    | `':'` = 0x3A |
| 11    | `';'` = 0x3B |
| 12    | `'<'` = 0x3C |
| 13    | `'='` = 0x3D |
| 14    | `'>'` = 0x3E |
| 15    | `'?'` = 0x3F |
| 16    | `'0'` = 0x30 (wrap) |

MVP field widths are always ≤ 20 wchars (rounds 0-1 only) so the
wrap never triggers in production; a userland reproducer must
still mirror the byte-for-byte formula for future-proofing.

---

## 3. Seed bytes

The seed comes from `HKLM\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters\RegCallbackSeed`
as `REG_SZ`. `track-d-arm.ps1 -Enable` writes there the value of
`$prof.pci_hardwareid.randomize_seed` (32 hex chars).

The kernel stores the seed as raw bytes: `g_TrackDSeed[i] = (UCHAR)(wsrc[i] & 0xFF)`
for each wchar of the REG_SZ (excluding the trailing NUL), capped at
64 bytes. So a 32-char hex seed becomes 32 ASCII bytes in the
mixer input.

A userland reproducer must:

1. Read the same REG_SZ.
2. Take the low byte of each wchar (equivalent to ASCII encoding
   assuming the seed is 32 hex chars, which the PS script validates
   with regex `^[0-9a-fA-F]{32}$`).
3. Cap at 64 bytes.

---

## 4. Output-byte assembly

Given hash value `h` (unsigned 64-bit result of `Get-Fnv1a64Hash`
over the mixer input built in section 2), the kernel emits 16
uppercase-hex wchars per round:

```
outName[cursor + produced + i] = HEX_UPPER[(h >> (60 - i*4)) & 0xF]
    where HEX_UPPER = L"0123456789ABCDEF"
    for i = 0 .. min(15, remaining_field_length - 1)
```

I.e. the most-significant nibble comes first; the algorithm is
big-endian in the hex representation.

`cursor` starts at the position of the field value inside the real
name (9 for Ven, `prod-marker-end` for Prod, `rev-marker-end` for
Rev) and advances by `produced` as each round emits.

The wchar count of the output ALWAYS EQUALS the wchar count of the
real field — this is why the caller's `NameLength` never needs
mutation.

---

## 5. Non-field wchars

Everything outside the three token values — the `Disk&Ven_` prefix
(9 wchars), the `&Prod_` marker (6 wchars, present iff Prod field
exists), the `&Rev_` marker (5 wchars, present iff Rev field exists),
and any tail characters past the last recognized field — is copied
from the real name UNCHANGED.

The kernel initializes the output buffer with a full copy of the real
name via `RtlCopyMemory` before overwriting the field ranges, so
unrecognized chars pass through as a byte-for-byte copy.

---

## 6. Worked example

Real subkey name (35 wchars):
```
Disk&Ven_KINGSTON&Prod_SA400S37480G
```

Seed (32 hex chars):
```
1a2b3c4d5e6f708192a3b4c5d6e7f809
```

Ven field:
- Value = `KINGSTON` (8 wchars)
- Mixer input for round 0:
  ```
  53 43 53 49 5F 56 45 4E 7C   # "SCSI_VEN|"
  31 61 32 62 33 63 34 64      # "1a2b3c4d" (seed bytes, ASCII)
  35 65 36 66 37 30 38 31 39
  32 61 33 62 34 63 35 64 36
  65 37 66 38 30 39            # ... rest of seed
  7C                            # "|"
  4B 00 49 00 4E 00 47 00      # "K\0I\0N\0G\0" (UTF-16LE of KINGSTON)
  53 00 54 00 4F 00 4E 00      # "S\0T\0O\0N\0"
  7C                            # "|"
  30                            # "0" (round 0)
  ```
- `h = Get-Fnv1a64Hash(<above bytes>)` — 64-bit result, e.g. `0xABCDEF0123456789`.
- Emit 8 hex uppercase chars: `ABCDEF01` (most-significant first,
  truncated because field is only 8 wchars).

Prod field:
- Value = `SA400S37480G` (12 wchars)
- Same recipe with `SCSI_PROD|` (10-byte domain).
- Emit 12 hex uppercase chars (still within round 0 since 12 ≤ 16).

Resulting synthetic subkey name:
```
Disk&Ven_ABCDEF01&Prod_1234567890AB
```
(the actual hex depends on the seed and real values; example illustrative).

---

## 7. Reference implementation pointer

- Kernel source of truth: `driver/rstflt.c` — see `TrackDFillTokenFnv`
  and `TrackDBuildSyntheticName`.
- FNV-1a-64 primitive (reusable in userland): `scripts/spoof-pci-hardwareid.ps1`
  `Get-Fnv1a64Hash` function.
- Kickoff and MVP scope: `docs/track-d-kernel-registry-callback-kickoff.md`.
- Design decisions and adversarial-review findings that shaped this
  spec: `docs/postmortem-v5-track-d/incident-v500-mvp-integration.md`.

---

## 8. Version history

- **2026-09-01** — v5.0.0 initial. Domain-tag inventory
  (`SCSI_VEN|` / `SCSI_PROD|` / `SCSI_REV|`) established. UTF-16LE
  real-field bytes canonicalized. Round-byte wrap past round 9
  documented (does not trigger for MVP SCSI field widths but a
  future expansion to wider fields MUST preserve the same formula).
