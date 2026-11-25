import crypto from 'node:crypto';
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { z, ZodError } from 'zod';
import { digest, hashPassword, randomToken, requireRole, signAccess, verifyAccess, verifyPassword } from './security.js';

const email = z.string().trim().email().max(254).transform((value) => value.toLowerCase());
const registerSchema = z.object({ email, password: z.string().min(15).max(128) }).strict();
const loginSchema = z.object({ email, password: z.string().min(1).max(128) }).strict();
const noteSchema = z.object({ title: z.string().trim().max(160).default(''), content: z.string().trim().min(1).max(5000) }).strict();
const uuid = z.string().uuid();
const commonPasswords = new Set(['password123456789', '123456789012345', 'qwertyuiopasdfgh']);

const getIp = (req) => req.ip || null;
const clientMetadata = (req) => ({ ip: getIp(req), userAgent: req.get('user-agent')?.slice(0, 512) || null });

export async function createApp({ pool, env }) {
  const app = express();
  const production = env.NODE_ENV === 'production';
  const refreshCookie = { httpOnly: true, secure: env.COOKIE_SECURE, sameSite: 'strict', path: '/api/auth', maxAge: env.REFRESH_TOKEN_DAYS * 86_400_000 };
  const csrfCookie = { httpOnly: false, secure: env.COOKIE_SECURE, sameSite: 'strict', path: '/', maxAge: 86_400_000 };
  const fakeHash = await hashPassword(randomToken());

  async function audit(userId, eventType, req, metadata = {}) {
    const { ip, userAgent } = clientMetadata(req);
    await pool.query('insert into app_private.audit_log (user_id,event_type,ip_address,user_agent,metadata) values ($1,$2,$3,$4,$5)', [userId, eventType, ip, userAgent, metadata]);
  }
  function setCsrf(res) {
    const token = randomToken();
    res.cookie('csrf', token, csrfCookie);
    return token;
  }
  function requireCsrf(req, res, next) {
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
    const cookie = req.cookies.csrf;
    const header = req.get('x-csrf-token');
    if (!cookie || !header || cookie.length !== header.length || !crypto.timingSafeEqual(Buffer.from(cookie), Buffer.from(header))) return res.status(403).json({ error: 'CSRF inválido' });
    return next();
  }
  async function requireAuth(req, res, next) {
    try {
      const [scheme, token, extra] = (req.get('authorization') || '').split(' ');
      if (scheme !== 'Bearer' || !token || extra) throw new Error('bad bearer');
      const claims = verifyAccess(token, env);
      const result = await pool.query(`select u.id,u.email_normalized as email,u.role,u.status
        from app_private.users u
        where u.id=$1 and u.status='active' and exists (
          select 1 from app_private.refresh_tokens r
          where r.user_id=u.id and r.family_id=$2 and r.revoked_at is null and r.expires_at > now()
        )`, [claims.sub, claims.sid]);
      if (!result.rowCount) throw new Error('revoked');
      req.user = result.rows[0];
      req.familyId = claims.sid;
      return next();
    } catch { return res.status(401).json({ error: 'Token inválido o vencido' }); }
  }
  async function checkLoginRate(req, res, next) {
    const identifier = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase().slice(0, 254) : '';
    const result = await pool.query(`select count(*)::int as attempts from app_private.login_attempts
      where account_identifier=$1 and ip_address is not distinct from $2 and success=false and created_at > now() - interval '15 minutes'`, [identifier, getIp(req)]);
    if (result.rows[0].attempts >= 5) return res.status(429).json({ error: 'Demasiados intentos. Intenta de nuevo más tarde.' });
    return next();
  }
  async function issue(client, user, familyId) {
    const token = randomToken();
    await client.query('insert into app_private.refresh_tokens (user_id,token_hash,family_id,expires_at) values ($1,$2,$3,now() + ($4::int * interval \'1 day\'))', [user.id, digest(token), familyId, env.REFRESH_TOKEN_DAYS]);
    return token;
  }
  function respondSession(res, user, familyId, token) {
    setCsrf(res);
    res.cookie('refresh', token, refreshCookie);
    res.json({ accessToken: signAccess(user, familyId, env), user: { id: user.id, email: user.email, role: user.role } });
  }

  app.disable('x-powered-by');
  app.set('trust proxy', false);
  app.use(helmet({ strictTransportSecurity: production ? undefined : false }));
  app.use(express.json({ limit: '16kb' }));
  app.use(cookieParser());
  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    const origin = req.get('origin');
    if (origin && origin !== env.APP_ORIGIN) return res.status(403).json({ error: 'Origen no autorizado' });
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    return next();
  });

  app.get('/api/health', async (_req, res) => { await pool.query('select 1'); res.json({ ok: true }); });
  app.get('/api/csrf', (_req, res) => res.json({ csrfToken: setCsrf(res) }));
  app.post('/api/auth/register', checkLoginRate, async (req, res) => {
    const data = registerSchema.parse(req.body);
    if (commonPasswords.has(data.password.toLowerCase())) return res.status(400).json({ error: 'Contraseña no permitida' });
    const passwordHash = await hashPassword(data.password);
    try {
      const user = await pool.query(`insert into app_private.users (email,password_hash,status) values ($1,$2,'pending_verification') returning id`, [data.email, passwordHash]);
      await audit(user.rows[0].id, 'REGISTER', req);
      // Sending is deliberately not simulated: a configured SMTP transport is required before production activation.
    } catch (error) { if (error.code !== '23505') throw error; }
    return res.status(202).json({ message: 'Solicitud procesada. Revisa tu correo si el servicio está configurado.' });
  });
  app.post('/api/auth/login', checkLoginRate, async (req, res) => {
    const data = loginSchema.parse(req.body);
    const result = await pool.query('select id,email_normalized as email,password_hash,role,status from app_private.users where email_normalized=$1', [data.email]);
    const user = result.rows[0];
    const valid = await verifyPassword(user?.password_hash || fakeHash, data.password);
    const success = Boolean(user && valid && user.status === 'active');
    await pool.query('insert into app_private.login_attempts (account_identifier,ip_address,success) values ($1,$2,$3)', [data.email, getIp(req), success]);
    if (!success) { await audit(user?.id || null, 'LOGIN_FAILED', req); return res.status(401).json({ error: 'Credenciales inválidas' }); }
    const familyId = crypto.randomUUID();
    const token = await issue(pool, user, familyId);
    await audit(user.id, 'LOGIN', req);
    return respondSession(res, user, familyId, token);
  });
  app.post('/api/auth/refresh', requireCsrf, async (req, res) => {
    const token = req.cookies.refresh;
    if (typeof token !== 'string') return res.sendStatus(401);
    const client = await pool.connect();
    try {
      await client.query('begin');
      const result = await client.query(`select r.*,u.email_normalized as email,u.role,u.status from app_private.refresh_tokens r join app_private.users u on u.id=r.user_id where r.token_hash=$1 for update`, [digest(token)]);
      const current = result.rows[0];
      if (!current || current.revoked_at || current.expires_at <= new Date() || current.status !== 'active') { await client.query('rollback'); return res.sendStatus(401); }
      if (current.used_at) { await client.query('update app_private.refresh_tokens set revoked_at=now() where family_id=$1', [current.family_id]); await client.query('commit'); await audit(current.user_id, 'TOKEN_REUSE', req); res.clearCookie('refresh', refreshCookie); return res.sendStatus(401); }
      await client.query('update app_private.refresh_tokens set used_at=now() where id=$1', [current.id]);
      const next = await issue(client, current, current.family_id);
      await client.query('commit');
      return respondSession(res, current, current.family_id, next);
    } catch (error) { await client.query('rollback'); throw error; } finally { client.release(); }
  });
  app.post('/api/auth/logout', requireCsrf, async (req, res) => {
    const token = req.cookies.refresh;
    if (typeof token === 'string') {
      const result = await pool.query('select family_id,user_id from app_private.refresh_tokens where token_hash=$1', [digest(token)]);
      if (result.rowCount) { await pool.query('update app_private.refresh_tokens set revoked_at=now() where family_id=$1', [result.rows[0].family_id]); await audit(result.rows[0].user_id, 'LOGOUT', req); }
    }
    return res.clearCookie('refresh', refreshCookie).sendStatus(204);
  });
  app.get('/api/me', requireAuth, (req, res) => res.json(req.user));
  app.get('/api/notes', requireAuth, async (req, res) => { const result = await pool.query('select id,title,content,created_at,updated_at from app_private.notes where user_id=$1 order by created_at desc', [req.user.id]); res.json(result.rows); });
  app.post('/api/notes', requireAuth, requireCsrf, async (req, res) => { const data = noteSchema.parse(req.body); const result = await pool.query('insert into app_private.notes (user_id,title,content) values ($1,$2,$3) returning id,title,content,created_at,updated_at', [req.user.id, data.title, data.content]); res.status(201).json(result.rows[0]); });
  app.delete('/api/notes/:id', requireAuth, requireCsrf, async (req, res) => { const id = uuid.parse(req.params.id); const result = await pool.query('delete from app_private.notes where id=$1 and user_id=$2', [id, req.user.id]); res.sendStatus(result.rowCount ? 204 : 404); });
  app.get('/api/admin/users', requireAuth, requireRole('admin'), async (_req, res) => { const result = await pool.query('select id,email_normalized as email,role,status,created_at from app_private.users order by created_at desc limit 100'); res.json(result.rows); });
  app.get('/api/admin/audit', requireAuth, requireRole('admin'), async (_req, res) => { const result = await pool.query('select id,user_id,event_type,ip_address,user_agent,metadata,created_at from app_private.audit_log order by id desc limit 100'); res.json(result.rows); });
  app.use((_req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));
  app.use((error, _req, res, _next) => {
    if (error instanceof ZodError) return res.status(400).json({ error: 'Datos inválidos', issues: error.issues.map((issue) => ({ field: issue.path.join('.'), message: issue.message })) });
    console.error('Internal API error:', error.code || error.name);
    return res.status(500).json({ error: 'Error interno' });
  });
  return app;
}
