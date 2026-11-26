import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  ARGON2_OPTIONS,
  buildTotpUri,
  decryptAesGcm,
  digest,
  encryptAesGcm,
  generateRecoveryCodes,
  generateTotpCode,
  generateTotpSecret,
  hashPassword,
  normalizeRecoveryCode,
  randomToken,
  signAccess,
  signMfaChallenge,
  verifyAccess,
  verifyMfaChallenge,
  verifyPassword,
  verifyTotpCode
} from './security.js';
import { checkCompromisedPassword } from './services/hibp.js';
import { loadEnv } from './config/env.js';

process.env.JWT_SECRET = 'test-only-secret-with-more-than-32-bytes';
const testDataKey = crypto.randomBytes(32).toString('base64');

test('Argon2id enforces >=19 MiB parameters and verifies passwords', async () => {
  assert.equal(ARGON2_OPTIONS.memoryCost >= 19_456, true);
  assert.equal(ARGON2_OPTIONS.timeCost >= 2, true);
  assert.equal(ARGON2_OPTIONS.parallelism >= 1, true);

  const started = performance.now();
  const hash = await hashPassword('a long test password for security lab');
  const elapsedMs = performance.now() - started;

  assert.match(hash, /^\$argon2id\$v=\d+\$m=19456,t=2,p=1\$/);
  assert.equal(elapsedMs > 5, true);
  assert.equal(await verifyPassword(hash, 'a long test password for security lab'), true);
  assert.equal(await verifyPassword(hash, 'wrong password'), false);
});

test('randomToken and SHA-256 digest', () => {
  const a = randomToken();
  const b = randomToken();
  assert.notEqual(a, b);
  assert.equal(a.length >= 43, true);
  assert.equal(digest(a).length, 64);
});

test('JWT access tokens validate claims and reject tampering or MFA challenge misuse', () => {
  const token = signAccess({ id: 1, role: 'user' }, 'test-family');
  const claims = verifyAccess(token);
  assert.equal(claims.sub, '1');
  assert.equal(claims.sid, 'test-family');
  assert.throws(() => verifyAccess(`${token}x`));

  const challenge = signMfaChallenge({ id: 'user-123' });
  assert.throws(() => verifyAccess(challenge.token));
  assert.equal(verifyMfaChallenge(challenge.token).sub, 'user-123');
});

test('AES-256-GCM encrypts with unique IV and rejects tampered ciphertext or tag', () => {
  const env = { DATA_KEY: testDataKey };
  const payload1 = encryptAesGcm('JBSWY3DPEHPK3PXP', env);
  const payload2 = encryptAesGcm('JBSWY3DPEHPK3PXP', env);

  assert.notEqual(payload1.iv, payload2.iv);
  assert.equal(decryptAesGcm(payload1, env), 'JBSWY3DPEHPK3PXP');

  const tampered = { ...payload1, ciphertext: Buffer.from('tampered').toString('base64') };
  assert.throws(() => decryptAesGcm(tampered, env));
});

test('TOTP secret, URI, generation, verification, and recovery codes', () => {
  const secret = generateTotpSecret();
  const uri = buildTotpUri({ issuer: 'Security Lab', label: 'user@example.test', secret });
  assert.match(uri, /^otpauth:\/\/totp\//);

  const code = generateTotpCode(secret);
  assert.match(code, /^\d{6}$/);
  assert.equal(verifyTotpCode({ secret, code }), true);
  assert.equal(verifyTotpCode({ secret, code: '000000' }) && code !== '000000', false);
  assert.equal(verifyTotpCode({ secret, code: 'abc' }), false);

  const recovery = generateRecoveryCodes(8);
  assert.equal(recovery.length, 8);
  assert.equal(normalizeRecoveryCode(recovery[0]).length, 12);
});

test('HIBP k-anonymity sends only 5-char prefix and fails open safely when offline', async () => {
  const localHit = await checkCompromisedPassword('password123456789', { enabled: true });
  assert.equal(localHit.compromised, true);
  assert.equal(localHit.source, 'local_blocklist');

  const repetitiveHit = await checkCompromisedPassword('zzzzzzzzzzzzzzz', { enabled: true });
  assert.equal(repetitiveHit.compromised, true);

  const password = 'correct-horse-battery-staple-unique-99';
  const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);

  let requestedUrl = '';
  const hitResult = await checkCompromisedPassword(password, {
    enabled: true,
    fetchImpl: async (url) => {
      requestedUrl = url;
      return {
        ok: true,
        text: async () => `${suffix}:42\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1`
      };
    }
  });
  assert.equal(requestedUrl, `https://api.pwnedpasswords.com/range/${prefix}`);
  assert.equal(requestedUrl.includes(suffix), false);
  assert.equal(hitResult.compromised, true);
  assert.equal(hitResult.source, 'hibp_k_anonymity');

  const fallbackResult = await checkCompromisedPassword(password, {
    enabled: true,
    fetchImpl: async () => {
      throw new Error('network down');
    }
  });
  assert.equal(fallbackResult.compromised, false);
  assert.equal(fallbackResult.degraded, true);
  assert.equal(fallbackResult.source, 'hibp_unavailable');
});

test('loadEnv enforces production security invariants', () => {
  assert.throws(() => loadEnv({
    NODE_ENV: 'production',
    DATABASE_URL: 'postgresql://u:p@127.0.0.1:5432/db',
    JWT_SECRET: 'short',
    COOKIE_SECURE: 'false'
  }));

  const valid = loadEnv({
    NODE_ENV: 'production',
    APP_ORIGIN: 'https://security-lab.vercel.app',
    DATABASE_URL: 'postgresql://u:p@127.0.0.1:5432/db',
    DB_SSL_CA: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----',
    JWT_SECRET: 'test-only-secret-with-more-than-32-bytes',
    DATA_KEY: testDataKey,
    COOKIE_SECURE: 'true'
  });
  assert.equal(valid.COOKIE_SECURE, true);
});
