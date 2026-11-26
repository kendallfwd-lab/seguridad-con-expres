# Documentación de Endpoints API

Base URL local: `http://localhost:5173/api` (proxy Vite hacia `http://127.0.0.1:3001/api`).
Todas las respuestas bajo `/api` incluyen `Cache-Control: no-store`.

## Salud y CSRF

| Método | Ruta | Auth | CSRF | Descripción | Códigos |
|---|---|---|---|---|---|
| `GET` | `/api/health` | Pública | No | Verifica conectividad con PostgreSQL (`select now()`) y estado SMTP | `200`, `500` |
| `GET` | `/api/csrf` | Pública | No | Emite cookie `csrf` y retorna `{ csrfToken }` | `200` |

## Autenticación, verificación y recuperación

| Método | Ruta | Auth | CSRF | Descripción | Códigos |
|---|---|---|---|---|---|
| `POST` | `/api/auth/register` | Pública | No | Registra cuenta `pending_verification` (`role='user'` fijo) y genera token de verificación | `202`, `400`, `429` |
| `POST` | `/api/auth/resend-verification` | Pública | No | Reemite token de verificación e invalida los anteriores | `202`, `400`, `429` |
| `POST` | `/api/auth/verify-email` | Pública | No | Consume token atómicamente y activa cuenta (`status='active'`) | `200`, `400`, `429` |
| `POST` | `/api/auth/login` | Pública | No | Valida credenciales (Argon2id + rate limit); entrega sesión o `mfaRequired: true` | `200`, `400`, `401`, `429` |
| `POST` | `/api/auth/mfa/verify-login` | Pública (`challengeToken`) | No | Verifica código TOTP o código de respaldo único y emite sesión | `200`, `400`, `401`, `429` |
| `POST` | `/api/auth/refresh` | Cookie `refresh` | Sí | Rota refresh token con bloqueo `FOR UPDATE` y detección de reutilización | `200`, `401`, `403` |
| `POST` | `/api/auth/logout` | Cookie `refresh` | Sí | Revoca la familia de tokens y limpia la cookie `refresh` | `204`, `403` |
| `POST` | `/api/auth/forgot-password` | Pública | No | Genera token de recuperación (1h) sin enumeración de cuentas | `202`, `400`, `429` |
| `POST` | `/api/auth/reset-password` | Pública (`token`) | No | Cambia contraseña y revoca todas las sesiones activas | `200`, `400`, `429` |
| `POST` | `/api/auth/change-password` | Bearer JWT | Sí | Reautentica `currentPassword`, cambia contraseña y revoca otras sesiones | `200`, `400`, `401`, `403` |

## Perfil, MFA y sesiones

| Método | Ruta | Auth | CSRF | Descripción | Códigos |
|---|---|---|---|---|---|
| `GET` | `/api/me` | Bearer JWT | No | Perfil del usuario autenticado | `200`, `401` |
| `GET` | `/api/mfa/status` | Bearer JWT | No | Estado de MFA y cantidad de códigos de respaldo restantes | `200`, `401` |
| `POST` | `/api/mfa/setup` | Bearer JWT | Sí | Reautentica y genera secreto TOTP cifrado con AES-256-GCM | `200`, `401`, `403` |
| `POST` | `/api/mfa/verify-setup` | Bearer JWT | Sí | Valida primer código TOTP, activa MFA y entrega 8 códigos de respaldo | `200`, `400`, `401`, `403` |
| `POST` | `/api/mfa/recovery-codes/regenerate` | Bearer JWT | Sí | Reautentica y reemplaza los 8 códigos de respaldo | `200`, `400`, `401`, `403` |
| `POST` | `/api/mfa/disable` | Bearer JWT | Sí | Reautentica contraseña + código TOTP/respaldo y desactiva MFA | `200`, `400`, `401`, `403` |
| `GET` | `/api/sessions` | Bearer JWT | No | Lista familias de sesión activas indicando `isCurrent` | `200`, `401` |
| `POST` | `/api/sessions/revoke-others` | Bearer JWT | Sí | Revoca todas las demás familias activas del usuario | `200`, `401`, `403` |
| `DELETE` | `/api/sessions/:familyId` | Bearer JWT | Sí | Revoca una familia de sesión específica | `204`, `400`, `401`, `403`, `404` |

## Notas privadas (Ownership)

| Método | Ruta | Auth | CSRF | Descripción | Códigos |
|---|---|---|---|---|---|
| `GET` | `/api/notes` | Bearer JWT | No | Lista notas del usuario autenticado | `200`, `401` |
| `GET` | `/api/notes/:id` | Bearer JWT | No | Obtiene una nota por UUID si pertenece al usuario | `200`, `400`, `401`, `404` |
| `POST` | `/api/notes` | Bearer JWT | Sí | Crea nota (`title`, `content`) | `201`, `400`, `401`, `403` |
| `PATCH` | `/api/notes/:id` | Bearer JWT | Sí | Actualiza nota propia | `200`, `400`, `401`, `403`, `404` |
| `DELETE` | `/api/notes/:id` | Bearer JWT | Sí | Elimina nota propia | `204`, `400`, `401`, `403`, `404` |

## Administración (RBAC `admin`)

| Método | Ruta | Auth | CSRF | Descripción | Códigos |
|---|---|---|---|---|---|
| `GET` | `/api/admin/users` | Bearer (`admin`) | No | Lista usuarios sin hashes ni secretos (`?status=` opcional) | `200`, `401`, `403` |
| `PATCH` | `/api/admin/users/:id` | Bearer (`admin`) | Sí | Cambia `status` o `role` (protege contra auto-bloqueo) | `200`, `400`, `401`, `403`, `404` |
| `GET` | `/api/admin/audit` | Bearer (`admin`) | No | Lista últimos 100 eventos de `audit_log` (`?eventType=` opcional) | `200`, `401`, `403` |
