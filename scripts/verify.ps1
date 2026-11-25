param([string]$ApiUrl='http://localhost:3001/api/health')
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Push-Location "$root/backend"
try { npm test; if ($LASTEXITCODE -ne 0) { throw 'Backend tests failed' } } finally { Pop-Location }
Push-Location "$root/frontend"
try { npm run build; if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed' } } finally { Pop-Location }
$response=Invoke-RestMethod -Uri $ApiUrl -TimeoutSec 15
if ($response.ok -ne $true) { throw 'Health check failed' }
Write-Host 'Tests, build y health correctos. Ejecutar tambien criterios restantes de ACCEPTANCE_CRITERIA.md.'
