import pg from 'pg';
import { loadEnv } from './env.js';

const { Pool } = pg;

export function createPool(env = loadEnv()) {
  const production = env.NODE_ENV === 'production';
  return new Pool({
    connectionString: env.DATABASE_URL,
    max: production ? 3 : 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    ssl: production ? { rejectUnauthorized: true, ca: env.DB_SSL_CA?.replace(/\\n/g, '\n') } : false
  });
}

export async function checkDatabase(pool) {
  const result = await pool.query('select current_database() as database, now() as time');
  return result.rows[0];
}
