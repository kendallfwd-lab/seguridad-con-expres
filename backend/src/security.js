import argon2 from 'argon2';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

const argonOptions = { type: argon2.argon2id, memoryCost: 19_456, timeCost: 2, parallelism: 1 };
export const hashPassword = (password) => argon2.hash(password, argonOptions);
export const verifyPassword = (hash, password) => argon2.verify(hash, password);
export const digest = (token) => crypto.createHash('sha256').update(token).digest('hex');
export const randomToken = () => crypto.randomBytes(32).toString('base64url');

function secret(env = process.env) {
  if (!env.JWT_SECRET || Buffer.byteLength(env.JWT_SECRET) < 32) throw new Error('JWT_SECRET debe tener al menos 32 bytes');
  return env.JWT_SECRET;
}
function options(env = process.env) {
  return { issuer: env.JWT_ISSUER || 'security-lab-api', audience: env.JWT_AUDIENCE || 'security-lab-web', algorithm: 'HS256' };
}
export function signAccess(user, familyId, env = process.env) {
  return jwt.sign({ sub: String(user.id), sid: familyId }, secret(env), { ...options(env), expiresIn: `${env.ACCESS_TOKEN_MINUTES || 15}m` });
}
export function verifyAccess(token, env = process.env) {
  return jwt.verify(token, secret(env), { ...options(env), algorithms: ['HS256'] });
}
export const requireRole = (...roles) => (req, res, next) => roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Permiso insuficiente' });
