# Guía de Despliegue — Vercel + Supabase

## Arquitectura de despliegue mismo origen en Vercel

El archivo raíz [vercel.json](file:///C:/Users/DELL1/.gemini/antigravity/scratch/seguridad-con-expres/vercel.json) configura:
- `installCommand`: `npm install && npm --prefix frontend install`
- `buildCommand`: `npm --prefix frontend run build`
- `outputDirectory`: `frontend/dist`
- `functions.api/index.js`: función serverless Node (`includeFiles: "backend/src/**"`) que adapta Express 5 sin llamar a `app.listen()`.
- `rewrites`:
  - `/api/(.*)` -> `/api/index.js`
  - `/((?!api/).*)` -> `/index.html` (SPA fallback)

## Variables de entorno requeridas en producción (Vercel)

- `NODE_ENV=production`
- `APP_ORIGIN=https://<tu-dominio>.vercel.app`
- `DATABASE_URL=<URI Transaction Pooler de Supabase con rol runtime de mínimo privilegio>`
- `DB_SSL_CA=<Certificado CA raíz de Supabase>`
- `JWT_SECRET=<secreto >= 32 bytes>`
- `JWT_ISSUER=security-lab-api`
- `JWT_AUDIENCE=security-lab-web`
- `ACCESS_TOKEN_MINUTES=15`
- `REFRESH_TOKEN_DAYS=7`
- `DATA_KEY=<clave AES-256 base64 de 32 bytes>`
- `COOKIE_SECURE=true`
- `TRUST_PROXY=1`
- `HIBP_CHECK_ENABLED=true`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` (obligatorios para envío real de correos de verificación/recuperación en producción)
