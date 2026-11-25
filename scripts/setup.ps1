$ErrorActionPreference = 'Stop'
Write-Host 'Diagnostico inicial (no instala ni modifica servicios automaticamente)'
foreach ($tool in @('node','npm','git','psql','pg_isready','winget','docker')) {
  $cmd = Get-Command $tool -ErrorAction SilentlyContinue
  if ($cmd) { Write-Host "$tool : disponible"; & $tool --version } else { Write-Warning "$tool no encontrado" }
}
Get-Service '*postgres*' -ErrorAction SilentlyContinue | Format-Table Name,Status
foreach ($port in @(3001,5173,5432)) { Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Select-Object LocalPort,State,OwningProcess }
Write-Host 'Codex: instala faltantes con IDs oficiales verificados y consentimiento cuando corresponda; continua segun MASTER_PROMPT.md.'
