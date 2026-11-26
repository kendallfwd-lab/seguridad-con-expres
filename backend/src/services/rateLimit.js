import net from 'node:net';

export function extractClientIp(req) {
  const raw = req.ip || req.socket?.remoteAddress || '';
  if (!raw) return null;
  const cleaned = raw.startsWith('::ffff:') ? raw.slice(7) : raw;
  return net.isIP(cleaned) ? cleaned : null;
}

export async function countAttempts(pool, { identifier, ip, windowMinutes = 15, onlyFailures = true }) {
  const failureClause = onlyFailures ? 'and success = false' : '';
  const result = await pool.query(
    `select count(*)::int as attempts
     from app_private.login_attempts
     where account_identifier = $1
       and ip_address is not distinct from $2::inet
       and created_at > now() - ($3::int * interval '1 minute')
       ${failureClause}`,
    [identifier, ip, windowMinutes]
  );
  return result.rows[0]?.attempts ?? 0;
}

export async function countIpAttempts(pool, { identifierPrefix, ip, windowMinutes = 15, onlyFailures = true }) {
  if (!ip) return 0;
  const failureClause = onlyFailures ? 'and success = false' : '';
  const result = await pool.query(
    `select count(*)::int as attempts
     from app_private.login_attempts
     where account_identifier like $1
       and ip_address = $2::inet
       and created_at > now() - ($3::int * interval '1 minute')
       ${failureClause}`,
    [`${identifierPrefix}%`, ip, windowMinutes]
  );
  return result.rows[0]?.attempts ?? 0;
}

export async function recordAttempt(pool, { identifier, ip, success }) {
  await pool.query(
    `insert into app_private.login_attempts (account_identifier, ip_address, success)
     values ($1, $2::inet, $3)`,
    [identifier.slice(0, 254), ip, Boolean(success)]
  );
}
