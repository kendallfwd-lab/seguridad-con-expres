import express from 'express';
import { z } from 'zod';
import { requireRole } from '../security.js';

const uuid = z.string().uuid();
const updateUserSchema = z.object({
  status: z.enum(['active', 'disabled', 'pending_verification']).optional(),
  role: z.enum(['user', 'admin']).optional()
}).strict().refine((data) => data.status !== undefined || data.role !== undefined, {
  message: 'Debes indicar status o role'
});

export function createAdminRouter({ pool, security }) {
  const router = express.Router();

  router.use(security.requireAuth, requireRole('admin'));

  router.get('/users', async (req, res) => {
    const statusFilter = typeof req.query.status === 'string' && ['active', 'disabled', 'pending_verification'].includes(req.query.status)
      ? req.query.status
      : null;
    const result = await pool.query(
      `select u.id, u.email_normalized as email, u.role, u.status, u.email_verified_at as "emailVerifiedAt",
              u.created_at as "createdAt", coalesce(m.enabled, false) as "mfaEnabled"
       from app_private.users u
       left join app_private.mfa_settings m on m.user_id = u.id
       where ($1::app_private.user_status is null or u.status = $1::app_private.user_status)
       order by u.created_at desc
       limit 100`,
      [statusFilter]
    );
    return res.json(result.rows);
  });

  router.patch('/users/:id', security.requireCsrf, async (req, res) => {
    const targetId = uuid.parse(req.params.id);
    const data = updateUserSchema.parse(req.body);
    if (targetId === req.user.id && (data.status === 'disabled' || data.role === 'user')) {
      return res.status(400).json({ error: 'No puedes deshabilitar o degradar tu propia cuenta administrativa' });
    }

    const client = await pool.connect();
    try {
      await client.query('begin');
      const result = await client.query(
        `update app_private.users
         set status = coalesce($1::app_private.user_status, status),
             role = coalesce($2::app_private.user_role, role),
             email_verified_at = case
               when $1::app_private.user_status = 'active' and email_verified_at is null then now()
               else email_verified_at
             end
         where id = $3
         returning id, email_normalized as email, role, status, email_verified_at as "emailVerifiedAt", created_at as "createdAt"`,
        [data.status ?? null, data.role ?? null, targetId]
      );
      if (!result.rowCount) {
        await client.query('rollback');
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }
      if (data.status === 'disabled') {
        await client.query(
          'update app_private.refresh_tokens set revoked_at = now() where user_id = $1 and revoked_at is null',
          [targetId]
        );
      }
      await security.audit(req.user.id, 'ADMIN_USER_UPDATED', req, {
        targetUserId: targetId,
        changes: data
      }, client);
      await client.query('commit');
      return res.json(result.rows[0]);
    } catch (error) {
      await client.query('rollback');
      throw error;
    } finally {
      client.release();
    }
  });

  router.get('/audit', async (req, res) => {
    const eventType = typeof req.query.eventType === 'string' && req.query.eventType.trim()
      ? req.query.eventType.trim().slice(0, 80)
      : null;
    const result = await pool.query(
      `select id, user_id as "userId", event_type as "eventType", ip_address as "ipAddress",
              user_agent as "userAgent", metadata, created_at as "createdAt"
       from app_private.audit_log
       where ($1::text is null or event_type = $1::text)
       order by id desc
       limit 100`,
      [eventType]
    );
    return res.json(result.rows);
  });

  return router;
}
