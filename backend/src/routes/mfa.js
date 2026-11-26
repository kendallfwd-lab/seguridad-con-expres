import express from 'express';
import { z } from 'zod';
import {
  buildTotpUri,
  decryptAesGcm,
  digest,
  encryptAesGcm,
  generateRecoveryCodes,
  generateTotpSecret,
  normalizeRecoveryCode,
  verifyPassword,
  verifyTotpCode
} from '../security.js';

const reauthSchema = z.object({ currentPassword: z.string().min(1).max(128) }).strict();
const verifySetupSchema = z.object({ code: z.string().trim().min(6).max(12) }).strict();
const disableMfaSchema = z.object({
  currentPassword: z.string().min(1).max(128),
  code: z.string().trim().min(6).max(32)
}).strict();

export function createMfaRouter({ pool, env, security }) {
  const router = express.Router();

  async function reauthenticate(req, currentPassword, action) {
    const result = await pool.query('select password_hash from app_private.users where id = $1', [req.user.id]);
    const valid = await verifyPassword(result.rows[0].password_hash, currentPassword);
    if (!valid) {
      await security.audit(req.user.id, 'REAUTH_FAILED', req, { action });
      return false;
    }
    return true;
  }

  router.get('/status', security.requireAuth, async (req, res) => {
    const [mfaResult, codesResult] = await Promise.all([
      pool.query('select enabled, enabled_at from app_private.mfa_settings where user_id = $1', [req.user.id]),
      pool.query('select count(*)::int as remaining from app_private.mfa_recovery_codes where user_id = $1 and used_at is null', [req.user.id])
    ]);
    const row = mfaResult.rows[0];
    return res.json({
      enabled: Boolean(row?.enabled),
      enabledAt: row?.enabled_at || null,
      remainingRecoveryCodes: codesResult.rows[0]?.remaining ?? 0
    });
  });

  router.post('/setup', security.requireAuth, security.requireCsrf, async (req, res) => {
    const data = reauthSchema.parse(req.body);
    if (!(await reauthenticate(req, data.currentPassword, 'mfa_setup'))) {
      return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    }

    const secret = generateTotpSecret();
    const encrypted = encryptAesGcm(secret, env);
    await pool.query(
      `insert into app_private.mfa_settings (user_id, encrypted_secret, enabled, enabled_at)
       values ($1, $2::jsonb, false, null)
       on conflict (user_id)
       do update set encrypted_secret = excluded.encrypted_secret, enabled = false, enabled_at = null`,
      [req.user.id, JSON.stringify(encrypted)]
    );
    await security.audit(req.user.id, 'MFA_SETUP_STARTED', req);

    return res.json({
      secret,
      otpauthUri: buildTotpUri({ issuer: env.JWT_ISSUER || 'Security Lab', label: req.user.email, secret })
    });
  });

  router.post('/verify-setup', security.requireAuth, security.requireCsrf, async (req, res) => {
    const data = verifySetupSchema.parse(req.body);
    const result = await pool.query('select encrypted_secret from app_private.mfa_settings where user_id = $1', [req.user.id]);
    const settings = result.rows[0];
    if (!settings) {
      return res.status(400).json({ error: 'Inicia primero la configuración MFA' });
    }

    const secret = decryptAesGcm(settings.encrypted_secret, env);
    if (!verifyTotpCode({ secret, code: data.code })) {
      await security.audit(req.user.id, 'MFA_SETUP_FAILED', req);
      return res.status(400).json({ error: 'Código TOTP inválido' });
    }

    const recoveryCodes = generateRecoveryCodes(8);
    const client = await pool.connect();
    try {
      await client.query('begin');
      await client.query('update app_private.mfa_settings set enabled = true, enabled_at = now() where user_id = $1', [req.user.id]);
      await client.query('delete from app_private.mfa_recovery_codes where user_id = $1', [req.user.id]);
      for (const code of recoveryCodes) {
        await client.query(
          'insert into app_private.mfa_recovery_codes (user_id, code_hash) values ($1, $2)',
          [req.user.id, digest(normalizeRecoveryCode(code))]
        );
      }
      await security.audit(req.user.id, 'MFA_ENABLED', req, {}, client);
      await client.query('commit');
      return res.json({ enabled: true, recoveryCodes });
    } catch (error) {
      await client.query('rollback');
      throw error;
    } finally {
      client.release();
    }
  });

  router.post('/recovery-codes/regenerate', security.requireAuth, security.requireCsrf, async (req, res) => {
    const data = reauthSchema.parse(req.body);
    if (!(await reauthenticate(req, data.currentPassword, 'mfa_recovery_regenerate'))) {
      return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    }

    const mfa = await pool.query('select enabled from app_private.mfa_settings where user_id = $1', [req.user.id]);
    if (!mfa.rows[0]?.enabled) {
      return res.status(400).json({ error: 'MFA no está habilitado' });
    }

    const recoveryCodes = generateRecoveryCodes(8);
    const client = await pool.connect();
    try {
      await client.query('begin');
      await client.query('delete from app_private.mfa_recovery_codes where user_id = $1', [req.user.id]);
      for (const code of recoveryCodes) {
        await client.query(
          'insert into app_private.mfa_recovery_codes (user_id, code_hash) values ($1, $2)',
          [req.user.id, digest(normalizeRecoveryCode(code))]
        );
      }
      await security.audit(req.user.id, 'MFA_RECOVERY_REGENERATED', req, {}, client);
      await client.query('commit');
      return res.json({ recoveryCodes });
    } catch (error) {
      await client.query('rollback');
      throw error;
    } finally {
      client.release();
    }
  });

  router.post('/disable', security.requireAuth, security.requireCsrf, async (req, res) => {
    const data = disableMfaSchema.parse(req.body);
    if (!(await reauthenticate(req, data.currentPassword, 'mfa_disable'))) {
      return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    }

    const client = await pool.connect();
    try {
      await client.query('begin');
      const settingsResult = await client.query(
        'select encrypted_secret, enabled from app_private.mfa_settings where user_id = $1 for update',
        [req.user.id]
      );
      const settings = settingsResult.rows[0];
      if (!settings?.enabled) {
        await client.query('rollback');
        return res.status(400).json({ error: 'MFA no está habilitado' });
      }

      const secret = decryptAesGcm(settings.encrypted_secret, env);
      let valid = verifyTotpCode({ secret, code: data.code });
      if (!valid) {
        const codeHash = digest(normalizeRecoveryCode(data.code));
        const codeMatch = await client.query(
          'select id from app_private.mfa_recovery_codes where user_id = $1 and code_hash = $2 and used_at is null for update',
          [req.user.id, codeHash]
        );
        valid = codeMatch.rowCount > 0;
      }

      if (!valid) {
        await client.query('rollback');
        await security.audit(req.user.id, 'MFA_DISABLE_FAILED', req);
        return res.status(401).json({ error: 'Código MFA inválido' });
      }

      await client.query('delete from app_private.mfa_recovery_codes where user_id = $1', [req.user.id]);
      await client.query('delete from app_private.mfa_settings where user_id = $1', [req.user.id]);
      await security.audit(req.user.id, 'MFA_DISABLED', req, {}, client);
      await client.query('commit');
      return res.json({ enabled: false });
    } catch (error) {
      await client.query('rollback');
      throw error;
    } finally {
      client.release();
    }
  });

  return router;
}
