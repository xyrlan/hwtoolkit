#Requires -Version 5.1
# ============================================================
#  test-smbios-blob.ps1 - v4.0.10
#
#  Offline validator for SMBIOS blobs. Ports ValidateSmbiosBlob()
#  from driver\rstflt.c (v4.0.10) to PowerShell so we can check a
#  blob without rebooting into the driver.
#
#  Modes:
#    -Live       Read HKLM\...\mssmbios\Data\SMBiosData and validate
#                the raw firmware blob. Needs elevation (registry ACL).
#    -Cached     Read HKLM\...\RstFlt\Parameters\SmbiosBlob (whatever
#                spoof-smbios.ps1 armed for the next boot) and validate.
#                Elevation needed if the driver key is ACL-restricted.
#    -File       Validate a REG_BINARY dump saved to disk. Use with
#                -Path <file>.
#    -Synthetic  Build a synthetic Hyper-V-shaped 1036-byte blob,
#                round-trip it through the same Parse-SmbiosStructures
#                / Build-SmbiosBlob code that spoof-smbios.ps1 uses, and
#                validate each stage. Reproducer for the v4.0.10 fix.
#
#  Exit code: 0 on PASS, 1 on FAIL (any tested blob rejected).
#
#  ASCII-only. PS 5.1 default (BOM-less UTF-8 is read as Windows-1252
#  by PS 5.1). No accented chars, no em-dashes.
# ============================================================

[CmdletBinding()]
param(
    [switch]$Live,
    [switch]$Cached,
    [switch]$Synthetic,
    [string]$File
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ($Live -or $Cached -or $Synthetic -or $File)) {
    Write-Host "Usage: .\test-smbios-blob.ps1 -Live|-Cached|-Synthetic|-File <path>" -ForegroundColor Yellow
    Write-Host "  -Live       Validate live mssmbios\Data blob"
    Write-Host "  -Cached     Validate the driver's cached SmbiosBlob (what will be replayed next boot)"
    Write-Host "  -File PATH  Validate a REG_BINARY dump saved to disk"
    Write-Host "  -Synthetic  Reproduce the v4.0.10 scan-window bug against a synthetic Hyper-V-like blob"
    exit 2
}

# ============================================================
#  Test-SmbiosBlobValid
#  Faithful PS port of ValidateSmbiosBlob() from driver\rstflt.c
#  (v4.0.10). Returns @{ok=$true} or
#  @{ok=$false; where='<check name>'; offset=<byte>}.
#
#  NOTE: this port includes the v4.0.10 fix (scan starts at i=8,
#  fallback is just `tableStart == 0`). To repro the pre-v4.0.10
#  behavior, pass -ScanFrom 0.
# ============================================================
function Test-SmbiosBlobValid {
    param(
        [byte[]]$Blob,
        [int]$ScanFrom = 8   # v4.0.10 default; pass 0 for pre-v4.0.10 repro
    )

    if ($null -eq $Blob) {
        return @{ ok = $false; where = 'null-blob'; offset = 0 }
    }
    $Length = $Blob.Length
    if ($Length -lt 32)    { return @{ ok = $false; where = 'length<32';    offset = 0 } }
    if ($Length -gt 65536) { return @{ ok = $false; where = 'length>65536'; offset = 0 } }

    # Scan window [ScanFrom, 64) for a Type 0/1/2/3 header with L>=4.
    $tableStart = 0
    $found = $false
    for ($i = $ScanFrom; ($i + 2) -le $Length -and $i -lt 64; $i++) {
        $t = $Blob[$i]
        $L = $Blob[$i + 1]
        if (($t -eq 0 -or $t -eq 1 -or $t -eq 2 -or $t -eq 3) -and
            $L -ge 4 -and ($i + $L) -le $Length) {
            $tableStart = $i
            $found = $true
            break
        }
    }

    if ($ScanFrom -eq 0) {
        # Pre-v4.0.10 fallback behavior
        if ($tableStart -eq 0 -and $Blob[0] -gt 127) {
            return @{ ok = $false; where = 'pre-v4.0.10 fallback: no-header && Blob[0]>127'; offset = 0 }
        }
    } else {
        # v4.0.10 tightened fallback: no match anywhere in [ScanFrom, 64) = malformed
        if (-not $found) {
            return @{ ok = $false; where = 'no plausible struct header in scan window'; offset = $ScanFrom }
        }
    }

    $p = $tableStart
    $sawEnd = $false
    while (($p + 2) -le $Length) {
        $type = $Blob[$p]
        $len  = $Blob[$p + 1]

        if ($len -lt 4) {
            return @{ ok = $false; where = ('len<4 (type={0} len={1})' -f $type, $len); offset = $p }
        }
        if (($p + $len) -gt $Length) {
            return @{ ok = $false; where = 'formatted overruns Length'; offset = $p }
        }

        $q = $p + $len
        if ($q -ge $Length) {
            return @{ ok = $false; where = 'string table start >= Length'; offset = $q }
        }

        if ($Blob[$q] -eq 0) {
            if (($q + 1) -ge $Length) {
                return @{ ok = $false; where = 'q+1>=Length'; offset = $q }
            }
            if ($Blob[$q + 1] -ne 0) {
                return @{ ok = $false; where = 'expected double NUL for empty string table'; offset = $q }
            }
            $p = $q + 2
        } else {
            $pos = $q
            $terminated = $false
            while ($pos -lt $Length) {
                $strEnd = $pos
                while ($strEnd -lt $Length -and $Blob[$strEnd] -ne 0) {
                    $strEnd++
                }
                if ($strEnd -ge $Length) {
                    return @{ ok = $false; where = 'unterminated string in string table'; offset = $pos }
                }
                if ($strEnd -eq $pos) {
                    $terminated = $true
                    $p = $pos + 1
                    break
                }
                $pos = $strEnd + 1
            }
            if (-not $terminated) {
                return @{ ok = $false; where = 'string table not terminated'; offset = $q }
            }
        }

        if ($type -eq 127) {
            $sawEnd = $true
            break
        }
        if ($p -ge $Length) {
            return @{ ok = $false; where = 'p>=Length after struct (no End-Of-Table)'; offset = $p }
        }
    }

    if (-not $sawEnd) {
        return @{ ok = $false; where = 'end-of-table (type 127) not reached'; offset = $p }
    }
    return @{ ok = $true }
}

function Format-HexAround {
    param([byte[]]$Blob, [int]$Offset, [int]$Radius = 16)
    if ($null -eq $Blob -or $Blob.Length -eq 0) { return '(empty)' }
    $start = [Math]::Max(0, $Offset - $Radius)
    $end   = [Math]::Min($Blob.Length - 1, $Offset + $Radius)
    $sb = New-Object System.Text.StringBuilder
    for ($i = $start; $i -le $end; $i++) {
        $marker = if ($i -eq $Offset) { '*' } else { ' ' }
        [void]$sb.AppendFormat('{0}{1:X2}', $marker, $Blob[$i])
    }
    return $sb.ToString()
}

function Report {
    param(
        [string]$Label,
        [byte[]]$Blob,
        $Result,
        [int]$ScanFrom = 8
    )
    $tag = if ($ScanFrom -eq 0) { ' [PRE-v4.0.10 SCAN]' } else { '' }
    Write-Host ("[{0}]{1} size={2}" -f $Label, $tag, $Blob.Length) -ForegroundColor Cyan
    if ($Result.ok) {
        Write-Host "  PASS" -ForegroundColor Green
        return $true
    }
    Write-Host ("  FAIL: where='{0}' offset={1}" -f $Result.where, $Result.offset) -ForegroundColor Red
    Write-Host ("  hex around offset: {0}" -f (Format-HexAround -Blob $Blob -Offset $Result.offset -Radius 16)) -ForegroundColor DarkGray
    return $false
}

# ============================================================
#  Parse / Build - verbatim copies from scripts\spoof-smbios.ps1
#  (Synthetic mode uses these; Live/Cached/File modes only run the
#  validator against the raw REG_BINARY.)
# ============================================================
function Parse-SmbiosStructures {
    param([byte[]]$Blob, [int]$StartOffset)
    $structures = [System.Collections.ArrayList]::new()
    $offset = $StartOffset
    while ($offset -lt $Blob.Length - 2) {
        $type = $Blob[$offset]
        $len  = $Blob[$offset + 1]
        if ($len -lt 4) { break }
        $formatted = New-Object byte[] $len
        [Array]::Copy($Blob, $offset, $formatted, 0, [Math]::Min([int]$len, $Blob.Length - $offset))
        $strOffset = $offset + $len
        $strings   = [System.Collections.ArrayList]::new()
        $nextOffset = $strOffset
        if ($strOffset -ge $Blob.Length) { break }
        if ($Blob[$strOffset] -eq 0) {
            $nextOffset = $strOffset + 1
            if ($nextOffset -lt $Blob.Length -and $Blob[$nextOffset] -eq 0) {
                $nextOffset++
            }
        } else {
            $pos = $strOffset
            while ($pos -lt $Blob.Length) {
                $strEnd = $pos
                while ($strEnd -lt $Blob.Length -and $Blob[$strEnd] -ne 0) {
                    $strEnd++
                }
                if ($strEnd -eq $pos) {
                    $nextOffset = $pos + 1
                    break
                }
                $str = [System.Text.Encoding]::ASCII.GetString($Blob, $pos, $strEnd - $pos)
                [void]$strings.Add($str)
                $pos = $strEnd + 1
            }
            if ($pos -ge $Blob.Length) { $nextOffset = $Blob.Length }
        }
        [void]$structures.Add([PSCustomObject]@{
            Type = $type; Length = $len; Formatted = $formatted; Strings = $strings
        })
        $offset = $nextOffset
    }
    return ,$structures
}

function Build-SmbiosBlob {
    param([byte[]]$Header, $Structures)
    $result = [System.Collections.Generic.List[byte]]::new()
    $result.AddRange([byte[]]$Header)
    foreach ($s in $Structures) {
        $result.AddRange([byte[]]$s.Formatted)
        if ($s.Strings.Count -eq 0) {
            $result.Add(0); $result.Add(0)
        } else {
            foreach ($str in $s.Strings) {
                if ([string]::IsNullOrEmpty($str)) { $str = " " }
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($str)
                $result.AddRange($bytes)
                $result.Add(0)
            }
            $result.Add(0)
        }
    }
    # v4.0.10 hardening (mirror of spoof-smbios.ps1)
    if ($Header.Length -eq 8 -and $result.Count -ge 8) {
        $rawLen = $result.Count - 8
        $result[4] = [byte]($rawLen -band 0xFF)
        $result[5] = [byte](($rawLen -shr 8)  -band 0xFF)
        $result[6] = [byte](($rawLen -shr 16) -band 0xFF)
        $result[7] = [byte](($rawLen -shr 24) -band 0xFF)
    }
    return ,$result.ToArray()
}

function Set-StructureString {
    param($Structure, [int]$StringIndex, [string]$NewValue)
    if ($StringIndex -le 0) { return }
    $idx = $StringIndex - 1
    while ($Structure.Strings.Count -le $idx) {
        [void]$Structure.Strings.Add("Default string")
    }
    $Structure.Strings[$idx] = $NewValue
}

# ============================================================
#  Synthetic blob (Hyper-V-shaped, 1036 bytes)
# ============================================================
function Get-SyntheticBlob {
    param([int]$TargetSize = 1036)
    $out = [System.Collections.Generic.List[byte]]::new()
    # Wrapper: [Used21CallingMethod=3, Maj=3, Min=0, DmiRev=0, RawSize DWORD LE]
    $out.Add(0x03); $out.Add(0x03); $out.Add(0x00); $out.Add(0x00)
    $out.Add(0x00); $out.Add(0x00); $out.Add(0x00); $out.Add(0x00)   # placeholder, backpatched
    $tableStart = $out.Count  # 8

    # Type 0 BIOS Info L=24, strings [Vendor, Version, Date]
    $t0 = New-Object byte[] 24
    $t0[0] = 0x00; $t0[1] = 0x18; $t0[2] = 0x00; $t0[3] = 0x00
    $t0[4] = 0x01; $t0[5] = 0x02; $t0[8] = 0x03
    $out.AddRange($t0)
    foreach ($s in @('OEM','1.0','09/01/2020')) {
        $out.AddRange([byte[]][System.Text.Encoding]::ASCII.GetBytes($s)); $out.Add(0)
    }
    $out.Add(0)

    # Type 1 System Info L=27
    $t1 = New-Object byte[] 27
    $t1[0] = 0x01; $t1[1] = 0x1B; $t1[2] = 0x01; $t1[3] = 0x00
    $t1[4] = 0x01; $t1[5] = 0x02; $t1[6] = 0x03; $t1[7] = 0x04
    $uuid = [byte[]](0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
                     0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00)
    for ($k=0; $k -lt 16; $k++) { $t1[8 + $k] = $uuid[$k] }
    $t1[24] = 0x06; $t1[25] = 0x05; $t1[26] = 0x06
    $out.AddRange($t1)
    foreach ($s in @('ContosoOEM','ContosoProd','1.0','SN12345','SKU-A','Fam')) {
        $out.AddRange([byte[]][System.Text.Encoding]::ASCII.GetBytes($s)); $out.Add(0)
    }
    $out.Add(0)

    # Type 2 Baseboard L=15
    $t2 = New-Object byte[] 15
    $t2[0] = 0x02; $t2[1] = 0x0F; $t2[2] = 0x02; $t2[3] = 0x00
    $t2[4] = 0x01; $t2[5] = 0x02; $t2[6] = 0x03; $t2[7] = 0x04; $t2[8] = 0x05
    $out.AddRange($t2)
    foreach ($s in @('ContosoOEM','BoardProd','1.0','BSN12345','AT')) {
        $out.AddRange([byte[]][System.Text.Encoding]::ASCII.GetBytes($s)); $out.Add(0)
    }
    $out.Add(0)

    # Type 3 Chassis L=22 (ChassisType byte = 3 Desktop)
    $t3 = New-Object byte[] 22
    $t3[0] = 0x03; $t3[1] = 0x16; $t3[2] = 0x03; $t3[3] = 0x00
    $t3[4] = 0x01; $t3[5] = 0x03; $t3[6] = 0x02; $t3[7] = 0x03; $t3[8] = 0x04
    $out.AddRange($t3)
    foreach ($s in @('ContosoOEM','1.0','CSN12345','AT')) {
        $out.AddRange([byte[]][System.Text.Encoding]::ASCII.GetBytes($s)); $out.Add(0)
    }
    $out.Add(0)

    # Type 127 End-Of-Table L=4
    $t127 = New-Object byte[] 4
    $t127[0] = 0x7F; $t127[1] = 0x04; $t127[2] = 0xFE; $t127[3] = 0x00
    $out.AddRange($t127)
    $out.Add(0); $out.Add(0)   # empty string table

    # Backpatch wrapper raw-size DWORD (bytes 4-7)
    $rawSize = $out.Count - $tableStart
    $out[4] = [byte]($rawSize -band 0xFF)
    $out[5] = [byte](($rawSize -shr 8) -band 0xFF)
    $out[6] = [byte](($rawSize -shr 16) -band 0xFF)
    $out[7] = [byte](($rawSize -shr 24) -band 0xFF)

    # Pad to TargetSize with zeros
    while ($out.Count -lt $TargetSize) { $out.Add(0) }
    if ($out.Count -gt $TargetSize) {
        $trimmed = New-Object byte[] $TargetSize
        [Array]::Copy($out.ToArray(), $trimmed, $TargetSize)
        return ,$trimmed
    }
    return ,$out.ToArray()
}

# ============================================================
#  Mode dispatch
# ============================================================
$failed = 0

function Read-RegBinary {
    param([string]$KeyPath, [string]$ValueName)
    if (-not (Test-Path $KeyPath)) {
        Write-Host ("  Registry key not found: {0}" -f $KeyPath) -ForegroundColor Red
        return $null
    }
    try {
        $item = Get-ItemProperty -Path $KeyPath -Name $ValueName -ErrorAction Stop
        return ,([byte[]]$item.$ValueName)
    } catch {
        Write-Host ("  Cannot read {0}\{1}: {2}" -f $KeyPath, $ValueName, $_) -ForegroundColor Red
        return $null
    }
}

if ($Live) {
    Write-Host "=== Live: HKLM\SYSTEM\CurrentControlSet\Services\mssmbios\Data\SMBiosData ===" -ForegroundColor Yellow
    $blob = Read-RegBinary "HKLM:\SYSTEM\CurrentControlSet\Services\mssmbios\Data" "SMBiosData"
    if ($null -ne $blob) {
        if (-not (Report -Label 'live mssmbios' -Blob $blob -Result (Test-SmbiosBlobValid -Blob $blob))) { $failed++ }
        # Also show pre-v4.0.10 verdict for A/B
        [void](Report -Label 'live mssmbios' -Blob $blob -Result (Test-SmbiosBlobValid -Blob $blob -ScanFrom 0) -ScanFrom 0)
    } else { $failed++ }
}

if ($Cached) {
    Write-Host "=== Cached: HKLM\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters\SmbiosBlob ===" -ForegroundColor Yellow
    $blob = Read-RegBinary "HKLM:\SYSTEM\CurrentControlSet\Services\RstFlt\Parameters" "SmbiosBlob"
    if ($null -ne $blob) {
        if (-not (Report -Label 'cached SmbiosBlob' -Blob $blob -Result (Test-SmbiosBlobValid -Blob $blob))) { $failed++ }
        [void](Report -Label 'cached SmbiosBlob' -Blob $blob -Result (Test-SmbiosBlobValid -Blob $blob -ScanFrom 0) -ScanFrom 0)
    } else { $failed++ }
}

if ($File) {
    Write-Host ("=== File: {0} ===" -f $File) -ForegroundColor Yellow
    if (-not (Test-Path $File)) {
        Write-Host "  File not found" -ForegroundColor Red
        $failed++
    } else {
        try {
            $blob = [System.IO.File]::ReadAllBytes((Resolve-Path $File))
            if (-not (Report -Label ('file ' + $File) -Blob $blob -Result (Test-SmbiosBlobValid -Blob $blob))) { $failed++ }
            [void](Report -Label ('file ' + $File) -Blob $blob -Result (Test-SmbiosBlobValid -Blob $blob -ScanFrom 0) -ScanFrom 0)
        } catch {
            Write-Host ("  Read failed: {0}" -f $_) -ForegroundColor Red
            $failed++
        }
    }
}

if ($Synthetic) {
    Write-Host "=== Synthetic: Hyper-V-shaped 1036-byte blob, Parse+Build round-trip ===" -ForegroundColor Yellow
    $raw = Get-SyntheticBlob -TargetSize 1036
    Write-Host ("Wrapper (first 8 bytes): {0}" -f (($raw[0..7] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '))

    # v4.0.10 scan (post-fix)
    Write-Host ""
    Write-Host "--- v4.0.10 scan (i=8) ---" -ForegroundColor White
    if (-not (Report -Label 'raw synthetic'          -Blob $raw -Result (Test-SmbiosBlobValid -Blob $raw))) { $failed++ }

    $structs = Parse-SmbiosStructures -Blob $raw -StartOffset 8
    Write-Host ("Parsed {0} structs: types=[{1}]" -f $structs.Count, (($structs | ForEach-Object { $_.Type }) -join ','))

    $header = New-Object byte[] 8
    [Array]::Copy($raw, 0, $header, 0, 8)
    $rebuilt = Build-SmbiosBlob -Header $header -Structures $structs
    if (-not (Report -Label 'rebuilt (no mods)'      -Blob $rebuilt -Result (Test-SmbiosBlobValid -Blob $rebuilt))) { $failed++ }

    $structs2 = Parse-SmbiosStructures -Blob $raw -StartOffset 8
    $t1 = $structs2 | Where-Object { $_.Type -eq 1 } | Select-Object -First 1
    if ($null -ne $t1) { Set-StructureString -Structure $t1 -StringIndex 2 -NewValue 'AsusROG' }
    $spoofed = Build-SmbiosBlob -Header $header -Structures $structs2
    if (-not (Report -Label 'spoofed (Type1 Prod)'   -Blob $spoofed -Result (Test-SmbiosBlobValid -Blob $spoofed))) { $failed++ }

    # Pre-v4.0.10 scan (should FAIL on all three)
    Write-Host ""
    Write-Host "--- Pre-v4.0.10 scan (i=0) - expected to FAIL, this is the bug ---" -ForegroundColor White
    [void](Report -Label 'raw synthetic'          -Blob $raw     -Result (Test-SmbiosBlobValid -Blob $raw     -ScanFrom 0) -ScanFrom 0)
    [void](Report -Label 'rebuilt (no mods)'      -Blob $rebuilt -Result (Test-SmbiosBlobValid -Blob $rebuilt -ScanFrom 0) -ScanFrom 0)
    [void](Report -Label 'spoofed (Type1 Prod)'   -Blob $spoofed -Result (Test-SmbiosBlobValid -Blob $spoofed -ScanFrom 0) -ScanFrom 0)
}

Write-Host ""
if ($failed -gt 0) {
    Write-Host ("Done: {0} test(s) FAILED under the v4.0.10 validator." -f $failed) -ForegroundColor Red
    exit 1
}
Write-Host "Done: all v4.0.10 checks PASSED." -ForegroundColor Green
exit 0
