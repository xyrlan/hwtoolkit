# ============================================================
#  _ui-common.ps1  -  shared UI helpers
#
#  Dot-source ao topo de cada script:
#      . "$PSScriptRoot\_ui-common.ps1"
#
#  ASCII puro (Windows PowerShell 5.1 sem BOM lidando com codepage).
#  check-consistency.ps1 e ASCII-only por design; qualquer alteracao
#  aqui deve manter ASCII (sem acentos, aspas smart, em-dashes).
# ============================================================

function Write-Section($t) { Write-Host ""; Write-Host ("== " + $t + " ==") -ForegroundColor Cyan }
function Write-OK($m)      { Write-Host ("  [OK]   " + $m) -ForegroundColor Green }
function Write-Info($m)    { Write-Host ("  [*]    " + $m) -ForegroundColor Gray }
function Write-Warn($m)    { Write-Host ("  [!]    " + $m) -ForegroundColor Yellow }
function Write-Err($m)     { Write-Host ("  [X]    " + $m) -ForegroundColor Red }
function Write-Gap($m)     { Write-Host ("  [GAP]  " + $m) -ForegroundColor Yellow }
