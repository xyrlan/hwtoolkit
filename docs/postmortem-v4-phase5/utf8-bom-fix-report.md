# UTF-8 BOM fix — HW Toolkit scripts/

Applied by Windows test session on 2026-08-30 01:36:26
during Phase 2 (generate profile) after PS 5.1 pt-BR locale
tokenizer misinterpreted UTF-8 multi-byte sequences (em-dash U+2014
and accented Portuguese chars) as Windows-1252 mojibake, breaking
the parser on generate-profile.ps1:275 (cascade from em-dash on line 45).

Root cause: 8 of 14 .ps1 files in scripts/ contain UTF-8 text but
lack a UTF-8 BOM, so PS 5.1 defaults to the system ANSI codepage.
Fix is purely encoding: prepend 3 bytes (0xEF 0xBB 0xBF) to the
start of each file. No semantic change — the file content is
byte-identical after the BOM.

Same class of bug that the v4.0 adversarial review caught in
check-consistency.ps1 line 584; not caught for the other 8 files.

Files modified (all under scripts/):

- generate-profile.ps1  (1360 non-ASCII bytes)
- manage-emac-uuid.ps1  (3 non-ASCII bytes)
- spoof-audio-guids.ps1  (3 non-ASCII bytes)
- spoof-disk-registry.ps1  (3 non-ASCII bytes)
- spoof-edid-full.ps1  (3 non-ASCII bytes)
- spoof-mac.ps1  (3 non-ASCII bytes)
- spoof-pci-hardwareid.ps1  (9 non-ASCII bytes)
- spoof-smbios.ps1  (36 non-ASCII bytes)
- spoof-volume-guid.ps1  (17 non-ASCII bytes)


Recommended follow-up: commit the BOM in a fix branch on the macOS
dev session. Optionally lint the repo to require BOM on any .ps1
containing non-ASCII bytes.
