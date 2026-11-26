# Configuración de Supabase — Security Lab

## Arquitectura en Supabase

- **Esquema privado**: todas las tablas de aplicación residen en `app_private`, fuera de `public` y `graphql_public`.
- **Exposición Data API**: `supabase/config.jsonc` mantiene `schemas = ["public", "graphql_public"]`, y la migración revoca explícitamente permisos en `app_private` a `PUBLIC`, `anon` y `authenticated`.
- **Migración versionada**: [20261125153217_initial_security_schema.sql](file:///C:/Users/DELL1/.gemini/antigravity/scratch/seguridad-con-expres/supabase/migrations/20261125153217_initial_security_schema.sql).
- **Conexión desde serverless (Vercel)**:
  - Usar **Transaction Pooler** (puerto `6543`) para `DATABASE_URL` en `runtime` (sin prepared statements nombrados; `pg` en `backend/src/config/database.js` usa consultas parametrizadas anónimas).
  - Usar conexión directa o **Session Pooler** (puerto `5432`) exclusivamente para migraciones (`supabase db push`).
  - **TLS validado**: proporcionar el certificado raíz CA de Supabase en `DB_SSL_CA` para `rejectUnauthorized: true`.
- **Rol runtime mínimo**: crear un rol PostgreSQL específico para runtime (sin `SUPERUSER`, sin `CREATEDB`, sin `BYPASSRLS`, con `USAGE` en `app_private` y solo `SELECT, INSERT, UPDATE, DELETE` en tablas/secuencias de `app_private`).

## Comandos de vinculación y migración

```powershell
cd backend
.\node_modules\.bin\supabase login
.\node_modules\.bin\supabase link --project-ref <PROJECT_REF> --workdir ..
.\node_modules\.bin\supabase db push --dry-run --workdir ..
.\node_modules\.bin\supabase db push --workdir ..
```
