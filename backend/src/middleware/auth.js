import crypto from 'node:crypto';
import { digest, randomToken, signAccess, verifyAccess } from '../security.js';
import { extractClientIp } from '../services/rateLimit.js';

export function createSecurityContext({ pool, env }) {
  const refreshCookieBase = {
    httpOnly: true,
    secure: env.COOKIE_SECURE,
    sameSite: 'strict',
    path: '/api/auth'
  };
  const refreshCookie = {
    ...refreshCookieBase,
    maxAge: env.REFRESH_TOKEN_DAYS * 86_400_000
  };
  const csrfCookie = {
    httpOnly: false,
    secure: env.COOKIE_SECURE,
    sameSite: 'strict',
    path: '/',
    maxAge: 86_400_000
  };

  function clientMetadata(req) {
    return {
      ip: extractClientIp(req),
      userAgent: req.get('user-agent')?.slice(0, 512) || null
    };
  }

  async function audit(userId, eventType, req, metadata = {}, db = pool) {
    const { ip, userAgent } = clientMetadata(req);
    await db.query(
      `insert into app_private.audit_log (user_id, event_type, ip_address, user_agent, metadata)
       values ($1, $2, $3::inet, $4, $5::jsonb)`,
      [userId, eventType, ip, userAgent, JSON.stringify(metadata)]
    );
  }

  function setCsrf(res) {
    const token = randomToken();
    res.cookie('csrf', token, csrfCookie);
    return token;
  }

  function requireCsrf(req, res, next) {
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
    const cookie = req.cookies?.csrf;
    const header = req.get('x-csrf-token');
    if (
      typeof cookie !== 'string' ||
      typeof header !== 'string' ||
      !cookie ||
      cookie.length !== header.length ||
      !crypto.timingSafeEqual(Buffer.from(cookie), Buffer.from(header))
    ) {
      return res.status(403).json({ error: 'CSRF inválido' });
    }
    return next();
  }

  async function requireAuth(req, res, next) {
    try {
      const [scheme, token, extra] = (req.get('authorization') || '').split(' ');
      if (scheme !== 'Bearer' || !token || extra) throw new Error('bad bearer');
      const claims = verifyAccess(token, env);
      const result = await pool.query(
        `select u.id, u.email_normalized as email, u.role, u.status, u.email_verified_at, u.created_at,
                coalesce(m.enabled, false) as mfa_enabled
         from app_private.users u
         left join app_private.mfa_settings m on m.user_id = u.id
         where u.id = $1
           and u.status = 'active'
           and exists (
             select 1 from app_private.refresh_tokens r
             where r.user_id = u.id
               and r.family_id = $2
               and r.revoked_at is null
               and r.expires_at > now()
           )`,
        [claims.sub, claims.sid]
      );
      if (!result.rowCount) throw new Error('revoked');
      const row = result.rows[0];
      req.user = {
        id: row.id,
        email: row.email,
        role: row.role,
        status: row.status,
        emailVerifiedAt: row.email_verified_at,
        createdAt: row.created_at,
        mfaEnabled: Boolean(row.mfa_enabled)
      };
      req.familyId = claims.sid;
      return next();
    } catch {
      return res.status(401).json({ error: 'Token inválido o vencido' });
    }
  }

  async function issueRefreshToken(client, user, familyId) {
    const token = randomToken();
    await client.query(
      `insert into app_private.refresh_tokens (user_id, token_hash, family_id, expires_at)
       values ($1, $2, $3, now() + ($4::int * interval '1 day'))`,
      [user.id, digest(token), familyId, env.REFRESH_TOKEN_DAYS]
    );
    return token;
  }

  function respondSession(res, user, familyId, refreshToken) {
    setCsrf(res);
    res.cookie('refresh', refreshToken, refreshCookie);
    return res.json({
      accessToken: signAccess(user, familyId, env),
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        mfaEnabled: Boolean(user.mfa_enabled ?? user.mfaEnabled)
      }
    });
  }

  return {
    refreshCookieBase,
    refreshCookie,
    audit,
    setCsrf,
    requireCsrf,
    requireAuth,
    issueRefreshToken,
    respondSession
  };
}
