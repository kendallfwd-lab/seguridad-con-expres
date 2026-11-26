import pg from 'pg';
import { loadEnv } from './env.js';

const { Pool } = pg;

function normalizePem(value) {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (trimmed.includes('-----BEGIN')) return trimmed.replace(/\\n/g, '\n');
  const decoded = Buffer.from(trimmed, 'base64').toString('utf8');
  return decoded.includes('-----BEGIN') ? decoded : trimmed.replace(/\\n/g, '\n');
}

export function createPool(env = loadEnv()) {
  const production = env.NODE_ENV === 'production';
  const sslCa = normalizePem(env.DB_SSL_CA);
  return new Pool({
    connectionString: env.DATABASE_URL,
    max: production ? 3 : 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    ssl: production || sslCa
      ? { rejectUnauthorized: true, ca: sslCa }
      : false
  });
}

export async function checkDatabase(pool) {
  const result = await pool.query('select current_database() as database, now() as time');
  return result.rows[0];
}
