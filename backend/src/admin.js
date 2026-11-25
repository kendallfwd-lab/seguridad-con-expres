import { createPool } from './config/database.js';
import { loadEnv } from './config/env.js';
import { hashPassword } from './security.js';

const env = loadEnv();
const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
const password = process.env.ADMIN_PASSWORD;
if (!email || !/^\S+@\S+\.\S+$/.test(email) || !password || password.length < 15 || password.length > 128) {
  throw new Error('Define ADMIN_EMAIL y ADMIN_PASSWORD (15-128 caracteres)');
}
const pool = createPool(env);
try {
  await pool.query(`insert into app_private.users (email,password_hash,role,status,email_verified_at)
    values ($1,$2,'admin','active',now())`, [email, await hashPassword(password)]);
  console.log('Administrador creado');
} catch (error) {
  console.error(error.code === '23505' ? 'El administrador ya existe' : error.message);
  process.exitCode = 1;
} finally { await pool.end(); }
