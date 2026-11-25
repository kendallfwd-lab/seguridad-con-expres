# Seguridad no negociable
- Secretos en variables de entorno; archivos .env ignorados; .env.example sin secretos. No imprimir DATABASE_URL ni tokens. TLS validado; nunca rejectUnauthorized:false en producción.
- Argon2id mínimo 19 MiB, 2 iteraciones, paralelismo 1; medir coste. Contraseñas mínimo 15 caracteres sin composición obligatoria; permitir al menos 64. No truncar silenciosamente. Hash falso para cuentas inexistentes.
- JWT algoritmo fijo, issuer/audience/exp, sub y sid; roles consultados en servidor; no confiar en datos del cliente. Refresh de alta entropía, hash, rotación con bloqueo de fila, detección de reutilización y revocación. Coordinar refresh concurrente en cliente.
- Cookies Secure en producción, HttpOnly, SameSite; CSRF en endpoints de cookie. CORS específico; no wildcard con credenciales. Validar proxy de confianza según host. Rate limiting compartido, no solo memoria serverless.
- SQL parametrizado, ownership en la propia consulta, denegar por defecto. Sin asignación de rol por registro. Rol runtime mínimo, esquema privado, sin exposición Data API. No usar service_role en navegador.
- Reset/verificación de correo con token aleatorio hash, vencimiento y consumo atómico. MFA TOTP con secreto AES-256-GCM, IV único, backup codes de un uso. Reautenticación para acciones sensibles.
- Auditoría sin secretos ni datos innecesarios; sanitizar errores y respuestas. No ejecutar pruebas destructivas en producción. Revisar dependencias, lockfiles y configuración antes de deploy.
