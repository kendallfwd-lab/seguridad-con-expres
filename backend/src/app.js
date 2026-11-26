import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { ZodError } from 'zod';
import { parseAllowedOrigins, resolveTrustProxy } from './config/env.js';
import { createSecurityContext } from './middleware/auth.js';
import { createMailer } from './services/mailer.js';
import { createAuthRouter } from './routes/auth.js';
import { createMfaRouter } from './routes/mfa.js';
import { createNotesRouter } from './routes/notes.js';
import { createSessionsRouter } from './routes/sessions.js';
import { createAdminRouter } from './routes/admin.js';

export async function createApp({ pool, env, mailer, hibpChecker }) {
  const app = express();
  const production = env.NODE_ENV === 'production';
  const allowedOrigins = parseAllowedOrigins(env.APP_ORIGIN);
  const security = createSecurityContext({ pool, env });
  const mailService = mailer || createMailer(env);

  app.disable('x-powered-by');
  app.set('trust proxy', resolveTrustProxy(env));

  app.use(helmet({
    strictTransportSecurity: production ? undefined : false,
    contentSecurityPolicy: production ? undefined : false
  }));
  app.use(express.json({ limit: '16kb' }));
  app.use(cookieParser());

  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    const origin = req.get('origin');
    if (origin) {
      const normalized = origin.replace(/\/+$/, '');
      if (!allowedOrigins.includes(normalized)) {
        return res.status(403).json({ error: 'Origen no autorizado' });
      }
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Access-Control-Allow-Credentials', 'true');
      res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');
      res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
      res.set('Vary', 'Origin');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    return next();
  });

  app.get('/api/health', async (_req, res) => {
    const result = await pool.query('select now() as time');
    return res.json({
      ok: true,
      database: 'ok',
      smtpConfigured: mailService.configured,
      time: result.rows[0]?.time
    });
  });

  app.get('/api/csrf', (_req, res) => res.json({ csrfToken: security.setCsrf(res) }));
  app.get('/api/me', security.requireAuth, (req, res) => res.json(req.user));

  app.use('/api/auth', createAuthRouter({ pool, env, security, mailer: mailService, hibpChecker }));
  app.use('/api/mfa', createMfaRouter({ pool, env, security }));
  app.use('/api/notes', createNotesRouter({ pool, security }));
  app.use('/api/sessions', createSessionsRouter({ pool, security }));
  app.use('/api/admin', createAdminRouter({ pool, security }));

  app.use((_req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));

  app.use((error, _req, res, _next) => {
    if (error instanceof ZodError) {
      return res.status(400).json({
        error: 'Datos inválidos',
        issues: error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message
        }))
      });
    }
    if (error?.type === 'entity.parse.failed' || (error instanceof SyntaxError && error?.status === 400)) {
      return res.status(400).json({ error: 'JSON inválido' });
    }
    if (error?.type === 'entity.too.large') {
      return res.status(413).json({ error: 'Payload excede el límite permitido' });
    }
    console.error('Internal API error:', error.code || error.name);
    return res.status(500).json({ error: 'Error interno' });
  });

  return app;
}
