# Compile warning bug in rstflt.c v4.0 (found by Windows test session)

## Symptom
Under MSVC 14.44.35207 (VS Build Tools 2022 latest) with WDK/SDK 10.0.22621:

driver/rstflt.c(483): error C2220: warning treated as error
driver/rstflt.c(483): warning C4018: '>': signed/unsigned mismatch

Line 483 in the SMBIOS backup path:

    if ((st == STATUS_BUFFER_TOO_SMALL ||
         st == STATUS_BUFFER_OVERFLOW) &&
        curNeed > FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data))

curNeed is ULONG (unsigned). FIELD_OFFSET is defined in modern
sdkddkver.h / ntdef.h as ((LONG)(LONG_PTR)&(((type *)0)->field))
which is LONG (signed). Unsigned > Signed comparison trips C4018,
and rstflt makefile uses /W4 /WX so it becomes a hard error.

Author probably compiled with an older MSVC where FIELD_OFFSET
was ULONG, or where C4018 was not emitted for this specific
comparison. Adversarial review in the macOS session did not
catch it because macOS agents can only static-analyze without
running the actual compile pass.

## Workaround applied for this test session
Set env var CL=/wd4018 before invoking 02-compilar-driver.bat.
Suppresses C4018 (only that warning number), /W4 /WX remain
active for everything else. rstflt.sys compiled cleanly at
12800 bytes.

## Recommended real fix (in a dev-session PR)
Cast curNeed OR FIELD_OFFSET to a matching type:

    curNeed > (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data)

or

    (LONG)curNeed > FIELD_OFFSET(...)

Prefer (ULONG) cast on the FIELD_OFFSET side — offset is small,
non-negative, and the compare semantic is "did we get enough
bytes to hold at least the header?", which is a ULONG-space
comparison.

Grep the driver for other FIELD_OFFSET comparisons; there may
be more sites that would trip C4018 under stricter MSVC.

## Also documented in this session's scratchpad
- Session date: 2026-08-30 01:50:40
- Repo commit: 2301248
- MSVC version: 14.44.35207
- Windows SDK/WDK: 10.0.22621
