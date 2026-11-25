# Requires an elevated PowerShell session. It never writes credentials to Git.
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script from an elevated Administrator PowerShell session.'
}

function New-Secret {
  $bytes = New-Object byte[] 32
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','A').Replace('/','B')
}

function New-AesKey {
  $bytes = New-Object byte[] 32
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  return [Convert]::ToBase64String($bytes)
}

$root = Split-Path $PSScriptRoot -Parent
$report = Join-Path $root 'docs\POSTGRES_INSTALL_REPORT.md'
$postgresPassword = New-Secret
$migratorPassword = New-Secret
$runtimePassword = New-Secret
$jwtSecret = New-Secret
$dataKey = New-AesKey

choco install postgresql17 --yes --no-progress --params "'/Password:$postgresPassword'"
choco install pgadmin4 --yes --no-progress

$bin = 'C:\Program Files\PostgreSQL\17\bin'
$psql = Join-Path $bin 'psql.exe'
$ready = Join-Path $bin 'pg_isready.exe'
if (-not (Test-Path -LiteralPath $psql)) { throw 'psql.exe was not installed in the expected PostgreSQL 17 directory.' }
& $ready -h 127.0.0.1 -p 5432
if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL service is not ready on port 5432.' }

$env:PGPASSWORD = $postgresPassword
& $psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U postgres -d postgres -c "CREATE ROLE security_lab_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '$migratorPassword';"
& $psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U postgres -d postgres -c "CREATE ROLE security_lab_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '$runtimePassword';"
& $psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U postgres -d postgres -c 'CREATE DATABASE security_lab OWNER security_lab_migrator;'
& $psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U postgres -d postgres -c 'CREATE DATABASE security_lab_test OWNER security_lab_migrator;'

$env:PGPASSWORD = $migratorPassword
$migration = Join-Path $root 'supabase\migrations\20261125153217_initial_security_schema.sql'
& $psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U security_lab_migrator -d security_lab -f $migration
& $psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U security_lab_migrator -d security_lab_test -f $migration
& $psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U security_lab_migrator -d security_lab -c 'GRANT USAGE ON SCHEMA app_private TO security_lab_runtime; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app_private TO security_lab_runtime; GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app_private TO security_lab_runtime; ALTER DEFAULT PRIVILEGES IN SCHEMA app_private GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO security_lab_runtime; ALTER DEFAULT PRIVILEGES IN SCHEMA app_private GRANT USAGE, SELECT ON SEQUENCES TO security_lab_runtime;'
& $psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U security_lab_migrator -d security_lab_test -c 'GRANT USAGE ON SCHEMA app_private TO security_lab_runtime; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app_private TO security_lab_runtime; GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app_private TO security_lab_runtime;'

$envFile = Join-Path $root 'backend\.env'
@"
PORT=3001
NODE_ENV=development
APP_ORIGIN=http://localhost:5173
DATABASE_URL=postgresql://security_lab_runtime:$runtimePassword@127.0.0.1:5432/security_lab
DB_SSL_CA=
JWT_SECRET=$jwtSecret
JWT_ISSUER=security-lab-api
JWT_AUDIENCE=security-lab-web
ACCESS_TOKEN_MINUTES=15
REFRESH_TOKEN_DAYS=7
DATA_KEY=$dataKey
COOKIE_SECURE=false
"@ | Set-Content -LiteralPath $envFile -Encoding utf8 -NoNewline

Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
@"
# PostgreSQL local installation report

Installed at: $(Get-Date -Format o)

- PostgreSQL command line tools: $(& $psql --version)
- Service readiness: successful on `127.0.0.1:5432`.
- Development and test databases created with separate migrator and runtime roles.
- Versioned migration applied to both local databases.
- Runtime role was granted DML only in `app_private`; it has no database creation, role creation, schema creation, or DDL permissions.
- `backend/.env` was created locally and remains ignored by Git. No credential is recorded in this report.
"@ | Set-Content -LiteralPath $report -Encoding utf8
