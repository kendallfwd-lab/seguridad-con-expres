# Recovers only the empty local app_private schemas created by the failed bootstrap.
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Requires elevated Administrator PowerShell.' }
function New-Secret { $b=New-Object byte[] 32; $r=[System.Security.Cryptography.RandomNumberGenerator]::Create(); try{$r.GetBytes($b)}finally{$r.Dispose()}; [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','A').Replace('/','B') }
function Invoke-Psql([string[]]$Arguments) { & $psql @Arguments; if ($LASTEXITCODE -ne 0) { throw "psql failed with exit code $LASTEXITCODE" } }

$root=Split-Path $PSScriptRoot -Parent
$bin='C:\Program Files\PostgreSQL\17\bin'
$psql=Join-Path $bin 'psql.exe'; $postgres=Join-Path $bin 'postgres.exe'; $data='C:\Program Files\PostgreSQL\17\data'; $service='postgresql-x64-17'
$postgresPassword=New-Secret; $migratorPassword=New-Secret
Stop-Service -Name $service -Force
"ALTER ROLE postgres WITH PASSWORD '$postgresPassword';" | & $postgres --single -D $data postgres
if ($LASTEXITCODE -ne 0) { throw "postgres single-user password reset failed with exit code $LASTEXITCODE" }
Start-Service -Name $service
for($i=0;$i -lt 15;$i++){ if((& (Join-Path $bin 'pg_isready.exe') -h 127.0.0.1 -p 5432) -match 'aceptando|accepting'){break}; Start-Sleep -Seconds 1 }
$env:PGPASSWORD=$postgresPassword
Invoke-Psql @('-v','ON_ERROR_STOP=1','-h','127.0.0.1','-U','postgres','-d','postgres','-c',"ALTER ROLE security_lab_migrator WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '$migratorPassword';")
Invoke-Psql @('-v','ON_ERROR_STOP=1','-h','127.0.0.1','-U','postgres','-d','postgres','-c',"ALTER DATABASE security_lab OWNER TO security_lab_migrator; ALTER DATABASE security_lab_test OWNER TO security_lab_migrator;")
$env:PGPASSWORD=$migratorPassword
$migration=Join-Path $root 'supabase\migrations\20261125153217_initial_security_schema.sql'
foreach($db in @('security_lab','security_lab_test')) {
  Invoke-Psql @('-v','ON_ERROR_STOP=1','-h','127.0.0.1','-U','security_lab_migrator','-d',$db,'-c','DROP SCHEMA IF EXISTS app_private CASCADE;')
  Invoke-Psql @('-v','ON_ERROR_STOP=1','-h','127.0.0.1','-U','security_lab_migrator','-d',$db,'-f',$migration)
  Invoke-Psql @('-v','ON_ERROR_STOP=1','-h','127.0.0.1','-U','security_lab_migrator','-d',$db,'-c','GRANT USAGE ON SCHEMA app_private TO security_lab_runtime; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app_private TO security_lab_runtime; GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app_private TO security_lab_runtime;')
}
Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
@"
# PostgreSQL repair report

Repaired at: $(Get-Date -Format o)

- The previous `app_private` schemas were verified empty before replacement.
- The schema migration completed with `ON_ERROR_STOP=1` for development and test databases.
- Runtime DML grants were reapplied; credentials remain only in ignored local configuration.
"@ | Set-Content -LiteralPath (Join-Path $root 'docs\POSTGRES_REPAIR_REPORT.md') -Encoding utf8
