import express from 'express';
import { z } from 'zod';

const uuid = z.string().uuid();

export function createSessionsRouter({ pool, security }) {
  const router = express.Router();

  router.get('/', security.requireAuth, async (req, res) => {
    const result = await pool.query(
      `select family_id as "familyId",
              min(created_at) as "startedAt",
              max(created_at) as "lastRotatedAt",
              max(expires_at) as "expiresAt",
              count(*)::int as rotations
       from app_private.refresh_tokens
       where user_id = $1 and revoked_at is null and expires_at > now()
       group by family_id
       order by max(created_at) desc`,
      [req.user.id]
    );
    return res.json(result.rows.map((row) => ({
      ...row,
      isCurrent: row.familyId === req.familyId
    })));
  });

  router.post('/revoke-others', security.requireAuth, security.requireCsrf, async (req, res) => {
    const result = await pool.query(
      `update app_private.refresh_tokens
       set revoked_at = now()
       where user_id = $1 and family_id <> $2 and revoked_at is null`,
      [req.user.id, req.familyId]
    );
    await security.audit(req.user.id, 'OTHER_SESSIONS_REVOKED', req, { revokedRows: result.rowCount });
    return res.json({ revokedCount: result.rowCount });
  });

  router.delete('/:familyId', security.requireAuth, security.requireCsrf, async (req, res) => {
    const familyId = uuid.parse(req.params.familyId);
    const result = await pool.query(
      `update app_private.refresh_tokens
       set revoked_at = now()
       where user_id = $1 and family_id = $2 and revoked_at is null`,
      [req.user.id, familyId]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Sesión no encontrada' });
    await security.audit(req.user.id, 'SESSION_REVOKED', req, { familyId });
    if (familyId === req.familyId) {
      res.clearCookie('refresh', security.refreshCookieBase);
    }
    return res.sendStatus(204);
  });

  return router;
}
