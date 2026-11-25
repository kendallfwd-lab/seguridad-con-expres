import 'dotenv/config';
import { z } from 'zod';

const boolean = z.enum(['true', 'false']).transform((value) => value === 'true');
const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3001),
  APP_ORIGIN: z.string().url().default('http://localhost:5173'),
  DATABASE_URL: z.string().url(),
  DB_SSL_CA: z.string().optional(),
  JWT_SECRET: z.string().min(32),
  JWT_ISSUER: z.string().min(1).default('security-lab-api'),
  JWT_AUDIENCE: z.string().min(1).default('security-lab-web'),
  ACCESS_TOKEN_MINUTES: z.coerce.number().int().min(1).max(60).default(15),
  REFRESH_TOKEN_DAYS: z.coerce.number().int().min(1).max(30).default(7),
  DATA_KEY: z.string().optional(),
  COOKIE_SECURE: boolean.default(false),
  SMTP_HOST: z.string().min(1).optional(),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).optional(),
  SMTP_USER: z.string().min(1).optional(),
  SMTP_PASSWORD: z.string().min(1).optional(),
  SMTP_FROM: z.string().email().optional()
}).superRefine((value, context) => {
  if (value.NODE_ENV === 'production' && !value.COOKIE_SECURE) context.addIssue({ code: 'custom', message: 'COOKIE_SECURE debe ser true en producción', path: ['COOKIE_SECURE'] });
  if (value.NODE_ENV === 'production' && !value.DB_SSL_CA) context.addIssue({ code: 'custom', message: 'DB_SSL_CA es obligatorio en producción', path: ['DB_SSL_CA'] });
});

export function loadEnv(input = process.env) {
  return schema.parse(input);
}
