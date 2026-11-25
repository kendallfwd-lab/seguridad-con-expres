# Informe de entorno

Fecha de inspección: 2026-11-25 (America/Costa_Rica).

| Comprobación | Resultado |
| --- | --- |
| Node.js | `v24.19.0` |
| npm | `11.17.0` |
| Git | `2.53.0.windows.1` |
| Docker | `29.9.2` instalado; su configuración de usuario no fue legible desde el entorno actual |
| PostgreSQL / `psql` / `pg_isready` | No instalados o no disponibles en `PATH` |
| winget | No disponible en `PATH` |
| Chocolatey | Disponible en `C:\ProgramData\chocolatey\bin\choco.exe` |
| Servicios PostgreSQL | No se encontraron |
| Puertos 3001, 5173 y 5432 | Sin listeners detectados |
| Supabase CLI | No verificada: `npx supabase --version` quedó esperando descarga/red y se canceló sin cambios |

## Repositorio

El ZIP se extrajo en `C:\Users\DELL1\Desktop\bproyecto\express-security-lab`. No contenía historial Git. La aplicación inicial usa MySQL (`mysql2`) y carece de dependencias instaladas, configuración local y migraciones de PostgreSQL. No se detectaron credenciales en los archivos inspeccionados.

## Próximos pasos verificados

1. Instalar PostgreSQL y las herramientas cliente mediante un instalador oficial compatible, con elevación administrativa.
2. Crear roles y bases de datos locales separados para ejecución, migraciones y pruebas.
3. Sustituir MySQL por PostgreSQL y ejecutar las pruebas contra una base real.
