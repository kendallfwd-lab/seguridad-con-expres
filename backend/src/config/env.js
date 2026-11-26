import 'dotenv/config';
import { z } from 'zod';

const boolean = z.union([
  z.boolean(),
  z.enum(['true', 'false']).transform((value) => value === 'true')
]);
const trustProxySchema = z.union([
  z.literal('auto'),
  z.literal('false'),
  z.literal('true'),
  z.coerce.number().int().min(0).max(10)
]).default('auto');

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3001),
  APP_ORIGIN: z.string().min(1).default('http://localhost:5173'),
  DATABASE_URL: z.string().url(),
  DB_SSL_CA: z.string().optional(),
  JWT_SECRET: z.string().min(32),
  JWT_ISSUER: z.string().min(1).default('security-lab-api'),
  JWT_AUDIENCE: z.string().min(1).default('security-lab-web'),
  ACCESS_TOKEN_MINUTES: z.coerce.number().int().min(1).max(60).default(15),
  REFRESH_TOKEN_DAYS: z.coerce.number().int().min(1).max(30).default(7),
  DATA_KEY: z.string().optional(),
  COOKIE_SECURE: boolean.default(false),
  TRUST_PROXY: trustProxySchema,
  HIBP_CHECK_ENABLED: boolean.default(true),
  SMTP_HOST: z.string().min(1).optional(),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).optional(),
  SMTP_USER: z.string().min(1).optional(),
  SMTP_PASSWORD: z.string().min(1).optional(),
  SMTP_FROM: z.string().email().optional()
}).superRefine((value, context) => {
  const origins = value.APP_ORIGIN.split(',').map((item) => item.trim()).filter(Boolean);
  if (!origins.length) {
    context.addIssue({ code: 'custom', message: 'APP_ORIGIN debe incluir al menos un origen válido', path: ['APP_ORIGIN'] });
  }
  for (const origin of origins) {
    try {
      const parsed = new URL(origin);
      if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('protocol');
    } catch {
      context.addIssue({ code: 'custom', message: `Origen inválido en APP_ORIGIN: ${origin}`, path: ['APP_ORIGIN'] });
    }
  }
  if (value.DATA_KEY) {
    const keyBytes = Buffer.from(value.DATA_KEY, 'base64');
    if (keyBytes.length !== 32) {
      context.addIssue({ code: 'custom', message: 'DATA_KEY debe decodificar exactamente 32 bytes en base64', path: ['DATA_KEY'] });
    }
  }
  if (value.NODE_ENV === 'production') {
    if (!value.COOKIE_SECURE) {
      context.addIssue({ code: 'custom', message: 'COOKIE_SECURE debe ser true en producción', path: ['COOKIE_SECURE'] });
    }
    if (!value.DB_SSL_CA) {
      context.addIssue({ code: 'custom', message: 'DB_SSL_CA es obligatorio en producción', path: ['DB_SSL_CA'] });
    }
    if (!value.DATA_KEY) {
      context.addIssue({ code: 'custom', message: 'DATA_KEY es obligatorio en producción para cifrar secretos MFA', path: ['DATA_KEY'] });
    }
  }
});

export function parseAllowedOrigins(appOrigin) {
  return appOrigin
    .split(',')
    .map((origin) => origin.trim().replace(/\/+$/, ''))
    .filter(Boolean);
}

export function resolveTrustProxy(env) {
  if (env.TRUST_PROXY === 'false') return false;
  if (env.TRUST_PROXY === 'true') return 1;
  if (env.TRUST_PROXY === 'auto') return process.env.VERCEL === '1' ? 1 : false;
  return env.TRUST_PROXY;
}

export function loadEnv(input = process.env) {
  const sanitized = Object.fromEntries(
    Object.entries(input).map(([key, value]) => [key, value === '' ? undefined : value])
  );
  return schema.parse(sanitized);
}
