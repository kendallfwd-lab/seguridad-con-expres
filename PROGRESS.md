# Estado de migración — 2026-11-25

## Completado y guardado en GitHub

- Proyecto importado y publicado en `main`.
- Inventario de entorno y código original completado.
- MySQL eliminado de dependencias; backend iniciado para PostgreSQL con `pg`.
- CLI Supabase 3.4.0 instalada, inicializada localmente y migración versionada creada.
- Esquema privado `app_private` con tablas, restricciones, índices y revocaciones iniciales.
- Separación `app.js` / `server.js`, validación de entorno, JWT, Argon2id, SQL parametrizado y rotación transaccional de refresh tokens.
- Pruebas unitarias de criptografía/JWT: 3 aprobadas.

## Bloqueos activos

- PostgreSQL y pgAdmin aún no están instalados: Chocolatey requiere una sesión Windows realmente elevada y Windows informó reinicio pendiente.
- Docker Desktop no está activo; no se usó como sustituto de PostgreSQL.
- Falta autenticación y selección explícita de proyecto Supabase; no se modificó ningún recurso remoto.

## Próxima ejecución

1. Diagnosticar el reinicio pendiente sin reiniciar.
2. Abrir una sesión PowerShell elevada mediante UAC y verificar privilegios.
3. Instalar PostgreSQL 17 y pgAdmin, crear roles/bases locales separados y aplicar migración.
4. Ejecutar pruebas de integración/E2E reales y completar frontend, documentación, Supabase y despliegue autorizado.
