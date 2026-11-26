# Reporte de Pruebas — Security Lab

Fecha: 2026-11-25

## Resumen de ejecución local (PostgreSQL 17.12 real)

Comando ejecutado desde `backend/`:
```powershell
npm test
```

Resultado: **16 pruebas ejecutadas, 16 aprobadas, 0 fallidas**.

### Cobertura verificada

1. **Pruebas unitarias (`backend/src/security.test.js`)**
   - `Argon2id`: verificación de parámetros (`memoryCost >= 19456`, `timeCost >= 2`, `parallelism >= 1`), medición de tiempo (>5 ms) y validación positiva/negativa.
   - `randomToken` y `digest`: entropía >= 43 caracteres `base64url` y digest SHA-256 de 64 hex.
   - `JWT`: algoritmo `HS256`, `iss`/`aud`, rechazo ante manipulación y rechazo al intentar usar un `mfaChallengeToken` como `accessToken`.
   - `AES-256-GCM`: IV único por cifrado y rechazo al alterar `ciphertext` o `tag`.
   - `TOTP y códigos de respaldo`: secreto Base32, URI `otpauth://`, generación/verificación `otplib` v13.6.0 y códigos de respaldo normalizados.
   - `HIBP k-anonymity`: bloqueo local, patrón repetitivo, verificación de que solo se envían los primeros 5 caracteres hex del SHA-1 a la API y fallback fail-open documentado ante fallo de red.
   - `loadEnv`: rechazo de `JWT_SECRET` corto, `DATA_KEY` inválido o configuración insegura en `production`.

2. **Pruebas de integración contra PostgreSQL real (`security_lab_test` — `backend/src/integration.test.js`)**
   - Salud (`200`), cookie CSRF (`200`), bloqueo de origen no autorizado (`403`) y preflight CORS (`204`).
   - Registro: rechazo de contraseña corta (`400`), rechazo de inyección de `role: 'admin'` (`400`), rechazo de contraseña filtrada (`400`), bloqueo de login previo a verificación (`401`), invalidación de token previo al reenviar, expiración de token (`400`), verificación exitosa (`200`) y rechazo de reuso (`400`).
   - Login y rate limiting persistente: `401` sin token/con token falso, bloqueo `429` + `Retry-After: 900` al sexto intento dentro de 15 minutos.
   - Refresh rotation & reuse detection: rechazo sin CSRF (`403`), rotación válida (`200`), detección de replay (`401` + `TOKEN_REUSE` + revocación de familia), concurrencia simultánea en servidor (`[200, 401]`) y logout (`204`).
   - CRUD de notas y ownership: creación (`201`), payload SQL injection almacenado de forma segura sin ejecución, bloqueo `404` de lectura/edición/borrado desde otra cuenta, actualización (`200`) y eliminación (`204`).
   - RBAC administrativo: `403` para usuarios normales en `/api/admin/*`, `200` para admin sin exposición de hashes, deshabilitación de usuarios (`200`), bloqueo de auto-deshabilitación (`400`) y auditoría (`200`).
   - MFA TOTP: reautenticación obligatoria en setup (`401` si falla), secreto cifrado con `aes-256-gcm` en BD, 8 códigos de respaldo únicos, login con `challengeToken`, rechazo de replay de `challengeToken`, uso único de código de respaldo, login TOTP y desactivación con reautenticación.
   - Sesiones y recuperación de contraseña: listado de sesiones activas, revocación de otras sesiones, expiración de token de reset (`400`), reset exitoso con revocación total de sesiones y rechazo de reutilización.

3. **Prueba E2E sobre TCP HTTP real (`backend/src/e2e.test.js`)**
   - Flujo completo contra servidor HTTP en loopback + PostgreSQL `security_lab_test`: CSRF -> registro -> verificación -> login -> creación de nota -> setup MFA -> logout -> login con MFA -> refresh -> lectura persistida de notas.

4. **Build de frontend (`frontend/`)**
   - `npm run build` (`vite build`): **31 módulos transformados**, bundle generado en `frontend/dist` sin errores y verificación sin `localStorage`, `DATABASE_URL`, `JWT_SECRET`, `DATA_KEY` ni `service_role`.
