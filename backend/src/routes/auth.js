import crypto from 'node:crypto';
import express from 'express';
import { z } from 'zod';
import {
  decryptAesGcm,
  digest,
  hashPassword,
  normalizeRecoveryCode,
  randomToken,
  signMfaChallenge,
  verifyMfaChallenge,
  verifyPassword,
  verifyTotpCode
} from '../security.js';
import { checkCompromisedPassword } from '../services/hibp.js';
import { countAttempts, countIpAttempts, extractClientIp, recordAttempt } from '../services/rateLimit.js';

const emailSchema = z.string().trim().email().max(254).transform((value) => value.toLowerCase());
const passwordPolicySchema = z.string().min(15).max(128);

const registerSchema = z.object({ email: emailSchema, password: passwordPolicySchema }).strict();
const loginSchema = z.object({ email: emailSchema, password: z.string().min(1).max(128) }).strict();
const emailOnlySchema = z.object({ email: emailSchema }).strict();
const verifyEmailSchema = z.object({ token: z.string().trim().min(20).max(256) }).strict();
const resetPasswordSchema = z.object({ token: z.string().trim().min(20).max(256), newPassword: passwordPolicySchema }).strict();
const changePasswordSchema = z.object({ currentPassword: z.string().min(1).max(128), newPassword: passwordPolicySchema }).strict();
const mfaVerifyLoginSchema = z.object({
  challengeToken: z.string().min(20).max(1024),
  code: z.string().trim().min(4).max(32).optional(),
  recoveryCode: z.string().trim().min(8).max(32).optional()
}).strict().refine((data) => Boolean(data.code || data.recoveryCode), {
  message: 'Debes proporcionar un código TOTP o un código de respaldo'
});

export function createAuthRouter({ pool, env, security, mailer, hibpChecker }) {
  const router = express.Router();
  const checkPasswordSafety = hibpChecker || ((password) => checkCompromisedPassword(password, { enabled: env.HIBP_CHECK_ENABLED }));

  let fakeHashPromise;
  const getFakeHash = () => {
    if (!fakeHashPromise) fakeHashPromise = hashPassword(randomToken());
    return fakeHashPromise;
  };

  async function checkIpRateLimit(req, res, prefix, limit = 10) {
    const ip = extractClientIp(req);
    const attempts = await countIpAttempts(pool, { identifierPrefix: prefix, ip, windowMinutes: 15, onlyFailures: false });
    if (attempts >= limit) {
      res.set('Retry-After', '900');
      res.status(429).json({ error: 'Demasiadas solicitudes. Intenta de nuevo más tarde.' });
      return false;
    }
    return true;
  }

  async function checkLoginRate(req, res, next) {
    const ip = extractClientIp(req);
    const rawEmail = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase().slice(0, 254) : '';
    const identifier = `login:${rawEmail}`;
    const [accountFailures, ipFailures] = await Promise.all([
      countAttempts(pool, { identifier, ip, windowMinutes: 15, onlyFailures: true }),
      countIpAttempts(pool, { identifierPrefix: 'login:', ip, windowMinutes: 15, onlyFailures: true })
    ]);
    if (accountFailures >= 5 || ipFailures >= 20) {
      res.set('Retry-After', '900');
      return res.status(429).json({ error: 'Demasiados intentos. Intenta de nuevo más tarde.' });
    }
    return next();
  }

  router.post('/register', async (req, res) => {
    if (!(await checkIpRateLimit(req, res, 'register:', 10))) return;
    const data = registerSchema.parse(req.body);
    const ip = extractClientIp(req);
    await recordAttempt(pool, { identifier: `register:${data.email}`, ip, success: false });

    const safety = await checkPasswordSafety(data.password);
    if (safety.compromised) {
      return res.status(400).json({ error: 'La contraseña elegida es insegura o aparece en filtraciones conocidas' });
    }
    if (safety.degraded) {
      await security.audit(null, 'HIBP_CHECK_UNAVAILABLE', req, { context: 'register' });
    }

    const passwordHash = await hashPassword(data.password);
    let emailSent = false;
    const client = await pool.connect();
    try {
      await client.query('begin');
      const created = await client.query(
        `insert into app_private.users (email, password_hash, status)
         values ($1, $2, 'pending_verification')
         returning id, email_normalized as email`,
        [data.email, passwordHash]
      );
      const user = created.rows[0];
      const verificationToken = randomToken();
      await client.query(
        `insert into app_private.email_verification_tokens (user_id, token_hash, expires_at)
         values ($1, $2, now() + interval '24 hours')`,
        [user.id, digest(verificationToken)]
      );
      await security.audit(user.id, 'REGISTER', req, { status: 'pending_verification' }, client);
      await client.query('commit');

      const delivery = await mailer.sendVerificationEmail({ to: user.email, token: verificationToken });
      emailSent = Boolean(delivery?.sent);
      if (emailSent) {
        await security.audit(user.id, 'EMAIL_VERIFICATION_SENT', req);
      }
    } catch (error) {
      await client.query('rollback');
      if (error.code !== '23505') throw error;
    } finally {
      client.release();
    }

    return res.status(202).json({
      message: emailSent
        ? 'Solicitud procesada. Revisa tu correo para verificar la cuenta.'
        : 'Solicitud procesada. SMTP no configurado en este entorno; el envío de correo requiere configuración SMTP real.',
      emailSent
    });
  });

  router.post('/resend-verification', async (req, res) => {
    const data = emailOnlySchema.parse(req.body);
    const ip = extractClientIp(req);
    const identifier = `verify-resend:${data.email}`;
    const attempts = await countAttempts(pool, { identifier, ip, windowMinutes: 15, onlyFailures: false });
    if (attempts >= 5) {
      res.set('Retry-After', '900');
      return res.status(429).json({ error: 'Demasiadas solicitudes. Intenta de nuevo más tarde.' });
    }
    await recordAttempt(pool, { identifier, ip, success: false });

    let emailSent = false;
    const result = await pool.query(
      `select id, email_normalized as email, status
       from app_private.users
       where email_normalized = $1`,
      [data.email]
    );
    const user = result.rows[0];
    if (user && user.status === 'pending_verification') {
      const token = randomToken();
      const client = await pool.connect();
      try {
        await client.query('begin');
        await client.query(
          `update app_private.email_verification_tokens
           set used_at = now()
           where user_id = $1 and used_at is null`,
          [user.id]
        );
        await client.query(
          `insert into app_private.email_verification_tokens (user_id, token_hash, expires_at)
           values ($1, $2, now() + interval '24 hours')`,
          [user.id, digest(token)]
        );
        await security.audit(user.id, 'EMAIL_VERIFICATION_REISSUED', req, {}, client);
        await client.query('commit');
      } catch (error) {
        await client.query('rollback');
        throw error;
      } finally {
        client.release();
      }
      const delivery = await mailer.sendVerificationEmail({ to: user.email, token });
      emailSent = Boolean(delivery?.sent);
    }

    return res.status(202).json({
      message: emailSent
        ? 'Si la cuenta está pendiente de verificación, se envió un nuevo correo.'
        : 'Solicitud procesada. SMTP no configurado en este entorno.',
      emailSent
    });
  });

  router.post('/verify-email', async (req, res) => {
    const ip = extractClientIp(req);
    const failures = await countIpAttempts(pool, { identifierPrefix: 'verify-token:', ip, windowMinutes: 15, onlyFailures: true });
    if (failures >= 10) {
      res.set('Retry-After', '900');
      return res.status(429).json({ error: 'Demasiados intentos de verificación. Intenta más tarde.' });
    }
    const data = verifyEmailSchema.parse(req.body);
    const client = await pool.connect();
    try {
      await client.query('begin');
      const tokenResult = await client.query(
        `select t.id, t.user_id, t.expires_at, t.used_at, u.status
         from app_private.email_verification_tokens t
         join app_private.users u on u.id = t.user_id
         where t.token_hash = $1
         for update of t`,
        [digest(data.token)]
      );
      const record = tokenResult.rows[0];
      if (!record || record.used_at || record.expires_at <= new Date()) {
        await client.query('rollback');
        await recordAttempt(pool, { identifier: 'verify-token:invalid', ip, success: false });
        return res.status(400).json({ error: 'Token de verificación inválido o vencido' });
      }
      await client.query('update app_private.email_verification_tokens set used_at = now() where id = $1', [record.id]);
      if (record.status === 'pending_verification') {
        await client.query(
          `update app_private.users
           set status = 'active', email_verified_at = coalesce(email_verified_at, now())
           where id = $1`,
          [record.user_id]
        );
      }
      await security.audit(record.user_id, 'EMAIL_VERIFIED', req, {}, client);
      await client.query('commit');
      return res.json({ ok: true, message: 'Correo verificado correctamente' });
    } catch (error) {
      await client.query('rollback');
      throw error;
    } finally {
      client.release();
    }
  });

  router.post('/login', checkLoginRate, async (req, res) => {
    const data = loginSchema.parse(req.body);
    const ip = extractClientIp(req);
    const result = await pool.query(
      `select u.id, u.email_normalized as email, u.password_hash, u.role, u.status,
              coalesce(m.enabled, false) as mfa_enabled
       from app_private.users u
       left join app_private.mfa_settings m on m.user_id = u.id
       where u.email_normalized = $1`,
      [data.email]
    );
    const user = result.rows[0];
    const valid = await verifyPassword(user?.password_hash || (await getFakeHash()), data.password);
    const success = Boolean(user && valid && user.status === 'active');

    await recordAttempt(pool, { identifier: `login:${data.email}`, ip, success });
    if (!success) {
      await security.audit(user?.id || null, 'LOGIN_FAILED', req, {
        reason: !user || !valid ? 'invalid_credentials' : user.status
      });
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    if (user.mfa_enabled) {
      const challenge = signMfaChallenge(user, env);
      await security.audit(user.id, 'MFA_CHALLENGE_ISSUED', req);
      return res.json({
        mfaRequired: true,
        challengeToken: challenge.token,
        user: { id: user.id, email: user.email, role: user.role, mfaEnabled: true }
      });
    }

    const familyId = crypto.randomUUID();
    const token = await security.issueRefreshToken(pool, user, familyId);
    await security.audit(user.id, 'LOGIN', req, { familyId });
    return security.respondSession(res, user, familyId, token);
  });

  router.post('/mfa/verify-login', async (req, res) => {
    const data = mfaVerifyLoginSchema.parse(req.body);
    let claims;
    try {
      claims = verifyMfaChallenge(data.challengeToken, env);
    } catch {
      return res.status(401).json({ error: 'Desafío MFA inválido o vencido' });
    }

    const ip = extractClientIp(req);
    const mfaIdentifier = `mfa:${claims.sub}`;
    const failures = await countAttempts(pool, { identifier: mfaIdentifier, ip, windowMinutes: 15, onlyFailures: true });
    if (failures >= 5) {
      res.set('Retry-After', '900');
      return res.status(429).json({ error: 'Demasiados intentos MFA. Intenta de nuevo más tarde.' });
    }

    const client = await pool.connect();
    try {
      await client.query('begin');
      await client.query('select pg_advisory_xact_lock(hashtext($1))', [claims.jti]);

      const replayCheck = await client.query(
        `select 1 from app_private.audit_log
         where user_id = $1 and event_type = 'MFA_LOGIN_VERIFIED' and metadata->>'jti' = $2`,
        [claims.sub, claims.jti]
      );
      if (replayCheck.rowCount > 0) {
        await client.query('rollback');
        return res.status(401).json({ error: 'Desafío MFA ya utilizado' });
      }

      const userResult = await client.query(
        `select u.id, u.email_normalized as email, u.role, u.status, m.encrypted_secret, m.enabled
         from app_private.users u
         join app_private.mfa_settings m on m.user_id = u.id
         where u.id = $1 and u.status = 'active' and m.enabled = true`,
        [claims.sub]
      );
      const user = userResult.rows[0];
      if (!user) {
        await client.query('rollback');
        return res.status(401).json({ error: 'Sesión MFA no disponible' });
      }

      let verified = false;
      let method = 'totp';
      if (data.code) {
        const secret = decryptAesGcm(user.encrypted_secret, env);
        verified = verifyTotpCode({ secret, code: data.code });
      } else if (data.recoveryCode) {
        method = 'recovery_code';
        const codeHash = digest(normalizeRecoveryCode(data.recoveryCode));
        const codeResult = await client.query(
          `select id from app_private.mfa_recovery_codes
           where user_id = $1 and code_hash = $2 and used_at is null
           for update`,
          [user.id, codeHash]
        );
        if (codeResult.rowCount > 0) {
          await client.query('update app_private.mfa_recovery_codes set used_at = now() where id = $1', [codeResult.rows[0].id]);
          verified = true;
        }
      }

      if (!verified) {
        await client.query('rollback');
        await recordAttempt(pool, { identifier: mfaIdentifier, ip, success: false });
        await security.audit(user.id, 'MFA_LOGIN_FAILED', req, { method });
        return res.status(401).json({ error: 'Código MFA inválido' });
      }

      await recordAttempt(pool, { identifier: mfaIdentifier, ip, success: true });
      const familyId = crypto.randomUUID();
      const refreshToken = await security.issueRefreshToken(client, user, familyId);
      await security.audit(user.id, 'MFA_LOGIN_VERIFIED', req, { jti: claims.jti, method, familyId }, client);
      await client.query('commit');

      return security.respondSession(res, { ...user, mfa_enabled: true }, familyId, refreshToken);
    } catch (error) {
      await client.query('rollback');
      throw error;
    } finally {
      client.release();
    }
  });

  router.post('/refresh', security.requireCsrf, async (req, res) => {
    const token = req.cookies?.refresh;
    if (typeof token !== 'string' || !token) return res.sendStatus(401);

    const client = await pool.connect();
    try {
      await client.query('begin');
      const result = await client.query(
        `select r.*, u.email_normalized as email, u.role, u.status,
                coalesce(m.enabled, false) as mfa_enabled
         from app_private.refresh_tokens r
         join app_private.users u on u.id = r.user_id
         left join app_private.mfa_settings m on m.user_id = u.id
         where r.token_hash = $1
         for update of r`,
        [digest(token)]
      );
      const current = result.rows[0];
      if (!current || current.revoked_at || current.expires_at <= new Date() || current.status !== 'active') {
        await client.query('rollback');
        return res.sendStatus(401);
      }
      if (current.used_at) {
        await client.query('update app_private.refresh_tokens set revoked_at = now() where family_id = $1 and revoked_at is null', [current.family_id]);
        await security.audit(current.user_id, 'TOKEN_REUSE', req, { familyId: current.family_id }, client);
        await client.query('commit');
        res.clearCookie('refresh', security.refreshCookieBase);
        return res.sendStatus(401);
      }

      await client.query('update app_private.refresh_tokens set used_at = now() where id = $1', [current.id]);
      const nextToken = await security.issueRefreshToken(client, { id: current.user_id }, current.family_id);
      await client.query('commit');
      return security.respondSession(res, {
        id: current.user_id,
        email: current.email,
        role: current.role,
        mfa_enabled: current.mfa_enabled
      }, current.family_id, nextToken);
    } catch (error) {
      await client.query('rollback');
      throw error;
    } finally {
      client.release();
    }
  });

  router.post('/logout', security.requireCsrf, async (req, res) => {
    const token = req.cookies?.refresh;
    if (typeof token === 'string' && token) {
      const result = await pool.query('select family_id, user_id from app_private.refresh_tokens where token_hash = $1', [digest(token)]);
      if (result.rowCount) {
        await pool.query('update app_private.refresh_tokens set revoked_at = now() where family_id = $1 and revoked_at is null', [result.rows[0].family_id]);
        await security.audit(result.rows[0].user_id, 'LOGOUT', req, { familyId: result.rows[0].family_id });
      }
    }
    return res.clearCookie('refresh', security.refreshCookieBase).sendStatus(204);
  });

  router.post('/forgot-password', async (req, res) => {
    const data = emailOnlySchema.parse(req.body);
    const ip = extractClientIp(req);
    const identifier = `reset-req:${data.email}`;
    const attempts = await countAttempts(pool, { identifier, ip, windowMinutes: 15, onlyFailures: false });
    if (attempts >= 5) {
      res.set('Retry-After', '900');
      return res.status(429).json({ error: 'Demasiadas solicitudes de recuperación. Intenta más tarde.' });
    }
    await recordAttempt(pool, { identifier, ip, success: false });

    let emailSent = false;
    const result = await pool.query(
      `select id, email_normalized as email, status
       from app_private.users
       where email_normalized = $1`,
      [data.email]
    );
    const user = result.rows[0];
    if (user && user.status === 'active') {
      const resetToken = randomToken();
      const client = await pool.connect();
      try {
        await client.query('begin');
        await client.query('update app_private.password_reset_tokens set used_at = now() where user_id = $1 and used_at is null', [user.id]);
        await client.query(
          `insert into app_private.password_reset_tokens (user_id, token_hash, expires_at)
           values ($1, $2, now() + interval '1 hour')`,
          [user.id, digest(resetToken)]
        );
        await security.audit(user.id, 'PASSWORD_RESET_REQUESTED', req, {}, client);
        await client.query('commit');
      } catch (error) {
        await client.query('rollback');
        throw error;
      } finally {
        client.release();
      }

      const delivery = await mailer.sendPasswordResetEmail({ to: user.email, token: resetToken });
      emailSent = Boolean(delivery?.sent);
    }

    return res.status(202).json({
      message: emailSent
        ? 'Si la cuenta existe y está activa, enviamos instrucciones de recuperación a tu correo.'
        : 'Solicitud procesada. SMTP no configurado en este entorno; el envío de correo requiere configuración SMTP real.',
      emailSent
    });
  });

  router.post('/reset-password', async (req, res) => {
    const ip = extractClientIp(req);
    const failures = await countIpAttempts(pool, { identifierPrefix: 'reset-token:', ip, windowMinutes: 15, onlyFailures: true });
    if (failures >= 10) {
      res.set('Retry-After', '900');
      return res.status(429).json({ error: 'Demasiados intentos de restablecimiento. Intenta más tarde.' });
    }

    const data = resetPasswordSchema.parse(req.body);
    const safety = await checkPasswordSafety(data.newPassword);
    if (safety.compromised) {
      return res.status(400).json({ error: 'La contraseña elegida es insegura o aparece en filtraciones conocidas' });
    }

    const newHash = await hashPassword(data.newPassword);
    const client = await pool.connect();
    try {
      await client.query('begin');
      const tokenResult = await client.query(
        `select t.id, t.user_id, t.expires_at, t.used_at
         from app_private.password_reset_tokens t
         where t.token_hash = $1
         for update of t`,
        [digest(data.token)]
      );
      const record = tokenResult.rows[0];
      if (!record || record.used_at || record.expires_at <= new Date()) {
        await client.query('rollback');
        await recordAttempt(pool, { identifier: 'reset-token:invalid', ip, success: false });
        return res.status(400).json({ error: 'Token de recuperación inválido o vencido' });
      }

      await client.query('update app_private.password_reset_tokens set used_at = now() where id = $1', [record.id]);
      await client.query('update app_private.users set password_hash = $1 where id = $2', [newHash, record.user_id]);
      await client.query('update app_private.refresh_tokens set revoked_at = now() where user_id = $1 and revoked_at is null', [record.user_id]);
      await security.audit(record.user_id, 'PASSWORD_RESET_COMPLETED', req, {}, client);
      await client.query('commit');

      res.clearCookie('refresh', security.refreshCookieBase);
      return res.json({ ok: true, message: 'Contraseña restablecida y sesiones anteriores revocadas' });
    } catch (error) {
      await client.query('rollback');
      throw error;
    } finally {
      client.release();
    }
  });

  router.post('/change-password', security.requireAuth, security.requireCsrf, async (req, res) => {
    const data = changePasswordSchema.parse(req.body);
    const userResult = await pool.query('select password_hash from app_private.users where id = $1', [req.user.id]);
    const valid = await verifyPassword(userResult.rows[0].password_hash, data.currentPassword);
    if (!valid) {
      await security.audit(req.user.id, 'REAUTH_FAILED', req, { action: 'change_password' });
      return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    }
    if (data.currentPassword === data.newPassword) {
      return res.status(400).json({ error: 'La nueva contraseña debe ser distinta a la actual' });
    }
    const safety = await checkPasswordSafety(data.newPassword);
    if (safety.compromised) {
      return res.status(400).json({ error: 'La nueva contraseña es insegura o aparece en filtraciones conocidas' });
    }

    const newHash = await hashPassword(data.newPassword);
    const client = await pool.connect();
    try {
      await client.query('begin');
      await client.query('update app_private.users set password_hash = $1 where id = $2', [newHash, req.user.id]);
      await client.query(
        'update app_private.refresh_tokens set revoked_at = now() where user_id = $1 and family_id <> $2 and revoked_at is null',
        [req.user.id, req.familyId]
      );
      await security.audit(req.user.id, 'PASSWORD_CHANGED', req, {}, client);
      await client.query('commit');
      return res.json({ ok: true, message: 'Contraseña actualizada y otras sesiones cerradas' });
    } catch (error) {
      await client.query('rollback');
      throw error;
    } finally {
      client.release();
    }
  });

  return router;
}
