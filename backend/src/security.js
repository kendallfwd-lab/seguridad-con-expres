import argon2 from 'argon2';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { OTP } from 'otplib';

export const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1
};

const totp = new OTP({ strategy: 'totp' });

export const hashPassword = (password) => argon2.hash(password, ARGON2_OPTIONS);
export const verifyPassword = (hash, password) => argon2.verify(hash, password);
export const digest = (token) => crypto.createHash('sha256').update(token).digest('hex');
export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

function secret(env = process.env) {
  if (!env.JWT_SECRET || Buffer.byteLength(env.JWT_SECRET) < 32) {
    throw new Error('JWT_SECRET debe tener al menos 32 bytes');
  }
  return env.JWT_SECRET;
}

function options(env = process.env) {
  return {
    issuer: env.JWT_ISSUER || 'security-lab-api',
    audience: env.JWT_AUDIENCE || 'security-lab-web',
    algorithm: 'HS256'
  };
}

export function signAccess(user, familyId, env = process.env) {
  return jwt.sign(
    { sub: String(user.id), sid: familyId, typ: 'access', jti: crypto.randomUUID() },
    secret(env),
    { ...options(env), expiresIn: `${env.ACCESS_TOKEN_MINUTES || 15}m` }
  );
}

export function verifyAccess(token, env = process.env) {
  const claims = jwt.verify(token, secret(env), { ...options(env), algorithms: ['HS256'] });
  if (claims.typ && claims.typ !== 'access') {
    throw new Error('Tipo de token inválido');
  }
  return claims;
}

export function signMfaChallenge(user, env = process.env) {
  const jti = crypto.randomUUID();
  const token = jwt.sign(
    { sub: String(user.id), jti, typ: 'mfa_challenge' },
    secret(env),
    {
      issuer: env.JWT_ISSUER || 'security-lab-api',
      audience: 'security-lab-mfa',
      algorithm: 'HS256',
      expiresIn: '5m'
    }
  );
  return { token, jti };
}

export function verifyMfaChallenge(token, env = process.env) {
  const claims = jwt.verify(token, secret(env), {
    issuer: env.JWT_ISSUER || 'security-lab-api',
    audience: 'security-lab-mfa',
    algorithms: ['HS256']
  });
  if (claims.typ !== 'mfa_challenge' || !claims.jti || !claims.sub) {
    throw new Error('Desafío MFA inválido');
  }
  return claims;
}

function getDataKey(env = process.env) {
  if (!env.DATA_KEY) {
    throw new Error('DATA_KEY no está configurada');
  }
  const key = Buffer.from(env.DATA_KEY, 'base64');
  if (key.length !== 32) {
    throw new Error('DATA_KEY debe tener 32 bytes (AES-256-GCM)');
  }
  return key;
}

export function encryptAesGcm(plaintext, env = process.env) {
  const key = getDataKey(env);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    alg: 'aes-256-gcm',
    v: 1,
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64')
  };
}

export function decryptAesGcm(payload, env = process.env) {
  if (!payload || payload.alg !== 'aes-256-gcm') {
    throw new Error('Formato de secreto cifrado inválido');
  }
  const key = getDataKey(env);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(payload.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(payload.tag, 'base64'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, 'base64')),
    decipher.final()
  ]);
  return plaintext.toString('utf8');
}

export function generateTotpSecret() {
  return totp.generateSecret();
}

export function buildTotpUri({ issuer, label, secret: totpSecret }) {
  return totp.generateURI({ issuer, label, secret: totpSecret });
}

export function verifyTotpCode({ secret: totpSecret, code }) {
  const normalized = String(code || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalized)) return false;
  const result = totp.verifySync({ secret: totpSecret, token: normalized, epochTolerance: 30 });
  return Boolean(result?.valid);
}

export function generateTotpCode(totpSecret) {
  return totp.generateSync({ secret: totpSecret });
}

export function generateRecoveryCodes(count = 8) {
  const codes = [];
  for (let i = 0; i < count; i += 1) {
    const raw = crypto.randomBytes(6).toString('hex').toUpperCase();
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`);
  }
  return codes;
}

export function normalizeRecoveryCode(code) {
  return String(code || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
}

export const requireRole = (...roles) => (req, res, next) =>
  roles.includes(req.user?.role) ? next() : res.status(403).json({ error: 'Permiso insuficiente' });
