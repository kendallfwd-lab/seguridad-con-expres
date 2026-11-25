# Security Lab — React + Express + MySQL
Laboratorio local basado en Seguridad completa en Express (27 diapositivas). El frontend es deliberadamente sencillo: el inspector HTTP permite practicar la seguridad del servidor.

## Instalación (Windows / PowerShell)
1. Instala Node.js 22+ y MySQL 8. Abre MySQL Workbench como administrador y ejecuta `database/schema.sql`. Crea un usuario local dedicado (cambia la contraseña de ejemplo):
```sql
CREATE USER 'security_lab'@'localhost' IDENTIFIED BY 'change_me';
GRANT SELECT, INSERT, UPDATE, DELETE ON security_lab.* TO 'security_lab'@'localhost';
```
2. En una terminal, desde la raíz:
```powershell
cd backend
Copy-Item .env.example .env
npm install
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```
Edita `.env`: pega el secreto generado en JWT_SECRET y configura las credenciales MySQL. No subas ese archivo a GitHub.
```powershell
npm test
npm run dev
```
3. En otra terminal, desde la raíz:
```powershell
cd frontend
npm install
npm run dev
```
Abre http://localhost:5173 (no uses 127.0.0.1 en la URL porque el origen está fijado). Vite usa un proxy de mismo origen; no se necesita CORS abierto. Para producción se requiere un proxy HTTPS de mismo origen, almacenamiento distribuido para rate limits, configuración de secretos y revisión adicional. El servidor escucha solo en loopback.

## Administrador inicial
Desde backend, en una terminal PowerShell:
```powershell
$env:ADMIN_EMAIL='admin@example.test'
$env:ADMIN_PASSWORD='Cambia esta frase privada por una propia'
npm run admin
Remove-Item Env:ADMIN_PASSWORD
Remove-Item Env:ADMIN_EMAIL
```
No hay administrador público ni endpoint de promoción. El script rechaza correos duplicados. Usa una contraseña distinta para cada cuenta. El registro público solo crea usuarios normales.

## Práctica
| Acción | Resultado esperado |
|---|---|
| Consultar perfil sin token o con token falso | 401 |
| Registrar contraseña corta | 400 (o validación HTML) |
| Login correcto | 200, JWT de 15 minutos |
| Login incorrecto | 401 genérico |
| Usuario normal consulta usuarios | 403 |
| Administrador consulta usuarios | 200 sin hashes |
| Crear nota autenticado | 201 |
| Otra cuenta intenta borrar esa nota | 404 |
| Renovar sesión | 200 y rotación de cookie |
| Cerrar sesión | 204, revocación de la familia |
| Sexto intento dentro de 15 minutos | 429 |

Para probar propiedad: registra dos cuentas, crea una nota con la primera y anota su ID. Cierra sesión, entra con la segunda, intenta eliminar por ID. El backend debe rechazarlo. Solo utiliza cuentas y datos del laboratorio.

## Alcance y límites
Implementado: Argon2id, JWT firmado con algoritmo/emisor/audiencia fijos, token de renovación opaco hasheado y rotado, revocación de familia y detección de reutilización, roles, propiedad de recursos, consultas parametrizadas, Helmet, validación Zod, límite por IP/cuenta, verificación estricta de Origin en escrituras, cookie HttpOnly y SameSite Strict, auditoría básica. Secure se activa en producción HTTPS. JWT vive solo en memoria; el botón Renovar sesión restaura una sesión tras recargar. El límite de IP se comparte entre registro y login. Los límites son locales al proceso y el reloj de MySQL debe estar en UTC para estas comparaciones. La lista de contraseñas comunes es ilustrativa, no una comprobación completa de filtraciones.

No implementado en esta versión: MFA, verificación de correo, recuperación de contraseña por correo, AES-GCM para campos sensibles, sesiones Redis, integración con listas de contraseñas comprometidas, despliegue HTTPS real ni CORS para orígenes separados. No es un sistema listo para producción. La validación de Origin protege las escrituras del navegador en esta arquitectura; para una arquitectura distinta revisar CSRF y CORS. No se incluyen credenciales reales. El inspector oculta access tokens y no imprime cookies.

## Estructura
- backend/src/server.js: API y middlewares
- backend/src/security.js: hash, firma y autorización
- backend/src/db.js: pool MySQL
- backend/src/admin.js: alta de admin local
- backend/src/security.test.js: pruebas unitarias
- frontend/src/main.jsx: interfaz de laboratorio
- database/schema.sql: tablas relacionales
