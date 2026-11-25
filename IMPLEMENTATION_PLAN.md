# Orden de ejecución
1. Inventario de entorno y repositorio; revisar git status, dependencias, puertos y esquema actual.
2. Instalar herramientas faltantes; crear DB local y DB de pruebas con roles separados. Ejecutar scripts/setup.ps1 como diagnóstico inicial.
3. Diseñar SQL PostgreSQL y migraciones; adaptar backend, scripts de admin y configuración; ejecutar tests de integración local.
4. Completar controles de seguridad del documento maestro y frontend; pruebas E2E, build y revisión de secretos.
5. Instalar CLI Supabase con versión fijada; revisar --help; autenticar y confirmar proyecto; aplicar migraciones verificadas y probar conectividad TLS y privilegios.
6. Adaptar runtime Vercel y configuración mismo origen; verificar variables y autorización; desplegar y ejecutar smoke tests.
7. Entregar evidencia por criterio, documentación y registro de tareas. Si falta acceso remoto, dejar todo local probado y explicar cómo continuar.
