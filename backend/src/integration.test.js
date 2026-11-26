import { after, before, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import request from 'supertest';
import pg from 'pg';
import { createApp } from './app.js';
import { loadEnv } from './config/env.js';
import { generateTotpCode, hashPassword } from './security.js';

const { Pool } = pg;

function buildTestDatabaseUrl() {
  const baseEnv = loadEnv();
  const url = new URL(baseEnv.DATABASE_URL);
  url.pathname = '/security_lab_test';
  return url.toString();
}

function extractCookie(setCookies, name) {
  if (!Array.isArray(setCookies)) return null;
  const match = setCookies.find((entry) => entry.startsWith(`${name}=`));
  if (!match) return null;
  return match.split(';')[0].slice(name.length + 1);
}

let pool;
let env;
let app;
let sentEmails;
let compromisedPasswordOverride;

const mockMailer = {
  configured: true,
  async sendVerificationEmail({ to, token }) {
    sentEmails.push({ type: 'verify', to, token });
    return { sent: true };
  },
  async sendPasswordResetEmail({ to, token }) {
    sentEmails.push({ type: 'reset', to, token });
    return { sent: true };
  }
};

before(async () => {
  const dbUrl = buildTestDatabaseUrl();
  env = loadEnv({
    NODE_ENV: 'test',
    APP_ORIGIN: 'http://localhost:5173',
    DATABASE_URL: dbUrl,
    JWT_SECRET: 'integration-test-secret-with-more-than-32-bytes',
    DATA_KEY: crypto.randomBytes(32).toString('base64'),
    COOKIE_SECURE: 'false',
    HIBP_CHECK_ENABLED: 'false'
  });
  pool = new Pool({ connectionString: dbUrl, max: 5 });
  app = await createApp({
    pool,
    env,
    mailer: mockMailer,
    hibpChecker: async (password) => {
      if (compromisedPasswordOverride && password === compromisedPasswordOverride) {
        return { compromised: true, source: 'mock_hibp', degraded: false };
      }
      if (password === 'password123456789') {
        return { compromised: true, source: 'local_blocklist', degraded: false };
      }
      return { compromised: false, source: 'mock_hibp', degraded: false };
    }
  });
});

beforeEach(async () => {
  sentEmails = [];
  compromisedPasswordOverride = null;
  await pool.query('delete from app_private.audit_log');
  await pool.query('delete from app_private.login_attempts');
  await pool.query('delete from app_private.users');
});

after(async () => {
  await pool?.end();
});

async function registerAndVerify(email, password = 'Correct Horse Battery Staple 2026!') {
  const reg = await request(app).post('/api/auth/register').send({ email, password });
  assert.equal(reg.status, 202);
  assert.equal(reg.body.emailSent, true);
  const mail = sentEmails.filter((item) => item.type === 'verify' && item.to === email.toLowerCase()).at(-1);
  assert.ok(mail?.token);
  const verify = await request(app).post('/api/auth/verify-email').send({ token: mail.token });
  assert.equal(verify.status, 200);
  return { email: email.toLowerCase(), password, verifyToken: mail.token };
}

async function loginAgent(email, password) {
  const agent = request.agent(app);
  const res = await agent.post('/api/auth/login').send({ email, password });
  assert.equal(res.status, 200);
  const csrf = extractCookie(res.headers['set-cookie'], 'csrf');
  assert.ok(csrf);
  return { agent, accessToken: res.body.accessToken, user: res.body.user, csrf };
}

test('health, CSRF cookie, and CORS origin allowlist', async () => {
  const health = await request(app).get('/api/health');
  assert.equal(health.status, 200);
  assert.equal(health.body.ok, true);
  assert.equal(health.body.database, 'ok');

  const badOrigin = await request(app).get('/api/health').set('Origin', 'https://evil.example');
  assert.equal(badOrigin.status, 403);

  const preflight = await request(app).options('/api/notes').set('Origin', 'http://localhost:5173');
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers['access-control-allow-origin'], 'http://localhost:5173');

  const csrfRes = await request(app).get('/api/csrf');
  assert.equal(csrfRes.status, 200);
  assert.ok(csrfRes.body.csrfToken);
});

test('registration rejects weak/compromised passwords, prevents role injection, and enforces single-use/expiring email verification', async () => {
  const shortRes = await request(app).post('/api/auth/register').send({ email: 'a@example.test', password: 'short' });
  assert.equal(shortRes.status, 400);

  const roleRes = await request(app).post('/api/auth/register').send({
    email: 'a@example.test',
    password: 'Correct Horse Battery Staple 2026!',
    role: 'admin'
  });
  assert.equal(roleRes.status, 400);

  compromisedPasswordOverride = 'LeakedPasswordFromBreach9999!';
  const leakedRes = await request(app).post('/api/auth/register').send({
    email: 'a@example.test',
    password: 'LeakedPasswordFromBreach9999!'
  });
  assert.equal(leakedRes.status, 400);

  await request(app).post('/api/auth/register').send({
    email: 'pending@example.test',
    password: 'Correct Horse Battery Staple 2026!'
  });

  // Cannot login before verification
  const unverifiedLogin = await request(app).post('/api/auth/login').send({
    email: 'pending@example.test',
    password: 'Correct Horse Battery Staple 2026!'
  });
  assert.equal(unverifiedLogin.status, 401);

  const firstToken = sentEmails[0].token;
  const resend = await request(app).post('/api/auth/resend-verification').send({ email: 'pending@example.test' });
  assert.equal(resend.status, 202);
  const secondToken = sentEmails[1].token;

  // Old verification token invalidated on resend
  const staleRes = await request(app).post('/api/auth/verify-email').send({ token: firstToken });
  assert.equal(staleRes.status, 400);

  // Expire second token in DB and confirm rejection
  await pool.query("update app_private.email_verification_tokens set expires_at = now() - interval '1 minute'");
  const expiredRes = await request(app).post('/api/auth/verify-email').send({ token: secondToken });
  assert.equal(expiredRes.status, 400);

  // Restore future expiry, verify once, and reject replay
  await pool.query("update app_private.email_verification_tokens set expires_at = now() + interval '1 hour'");
  const okRes = await request(app).post('/api/auth/verify-email').send({ token: secondToken });
  assert.equal(okRes.status, 200);

  const replayRes = await request(app).post('/api/auth/verify-email').send({ token: secondToken });
  assert.equal(replayRes.status, 400);
});

test('auth errors (401), persistent rate limiting (429), refresh rotation, reuse detection, and logout', async () => {
  await registerAndVerify('alice@example.test');

  assert.equal((await request(app).get('/api/me')).status, 401);
  assert.equal((await request(app).get('/api/me').set('Authorization', 'Bearer invalid.jwt.token')).status, 401);

  for (let i = 0; i < 5; i += 1) {
    const fail = await request(app).post('/api/auth/login').send({
      email: 'alice@example.test',
      password: 'wrong-password-12345'
    });
    assert.equal(fail.status, 401);
  }
  const locked = await request(app).post('/api/auth/login').send({
    email: 'alice@example.test',
    password: 'Correct Horse Battery Staple 2026!'
  });
  assert.equal(locked.status, 429);
  assert.equal(locked.headers['retry-after'], '900');

  // Clear login rate limit for valid login & refresh lifecycle test
  await pool.query('delete from app_private.login_attempts');
  const session = await loginAgent('alice@example.test', 'Correct Horse Battery Staple 2026!');

  const meRes = await session.agent.get('/api/me').set('Authorization', `Bearer ${session.accessToken}`);
  assert.equal(meRes.status, 200);
  assert.equal(meRes.body.email, 'alice@example.test');

  // Missing CSRF rejected with 403
  const missingCsrf = await session.agent.post('/api/auth/refresh');
  assert.equal(missingCsrf.status, 403);

  // Capture initial refresh cookie before rotating
  const loginCookies = session.agent.jar.getCookies({ domain: '127.0.0.1', path: '/api/auth', secure: false, script: false });
  const initialRefreshValue = loginCookies.find((c) => c.name === 'refresh')?.value;
  assert.ok(initialRefreshValue);

  const rotated = await session.agent.post('/api/auth/refresh').set('X-CSRF-Token', session.csrf);
  assert.equal(rotated.status, 200);
  assert.notEqual(rotated.body.accessToken, session.accessToken);
  const rotatedRefreshValue = extractCookie(rotated.headers['set-cookie'], 'refresh');
  assert.ok(rotatedRefreshValue);
  assert.notEqual(rotatedRefreshValue, initialRefreshValue);
  const nextCsrf = extractCookie(rotated.headers['set-cookie'], 'csrf');

  // Replay old refresh token -> 401 and family revoked
  const replay = await request(app)
    .post('/api/auth/refresh')
    .set('Cookie', [`refresh=${initialRefreshValue}`, `csrf=${nextCsrf}`])
    .set('X-CSRF-Token', nextCsrf);
  assert.equal(replay.status, 401);

  // Subsequent request with rotated accessToken fails because family was revoked
  const afterReuse = await session.agent.get('/api/me').set('Authorization', `Bearer ${rotated.body.accessToken}`);
  assert.equal(afterReuse.status, 401);

  // New session + logout invalidates session
  const session2 = await loginAgent('alice@example.test', 'Correct Horse Battery Staple 2026!');
  const logout = await session2.agent.post('/api/auth/logout').set('X-CSRF-Token', session2.csrf);
  assert.equal(logout.status, 204);
  const afterLogoutMe = await session2.agent.get('/api/me').set('Authorization', `Bearer ${session2.accessToken}`);
  assert.equal(afterLogoutMe.status, 401);
});

test('concurrent refresh triggers reuse detection on server without crashing', async () => {
  await registerAndVerify('concurrent@example.test');
  const session = await loginAgent('concurrent@example.test', 'Correct Horse Battery Staple 2026!');
  const cookieHeader = session.agent.jar
    .getCookies({ domain: '127.0.0.1', path: '/api/auth', secure: false, script: false })
    .map((c) => `${c.name}=${c.value}`);
  cookieHeader.push(`csrf=${session.csrf}`);

  const [r1, r2] = await Promise.all([
    request(app).post('/api/auth/refresh').set('Cookie', cookieHeader).set('X-CSRF-Token', session.csrf),
    request(app).post('/api/auth/refresh').set('Cookie', cookieHeader).set('X-CSRF-Token', session.csrf)
  ]);

  const statuses = [r1.status, r2.status].sort();
  assert.deepEqual(statuses, [200, 401]);
});

test('notes full CRUD, SQL injection parameterization, and strict ownership (404)', async () => {
  await registerAndVerify('owner@example.test');
  await registerAndVerify('other@example.test');
  const owner = await loginAgent('owner@example.test', 'Correct Horse Battery Staple 2026!');
  const other = await loginAgent('other@example.test', 'Correct Horse Battery Staple 2026!');

  const sqli = "'; DROP TABLE app_private.notes; --";
  const created = await owner.agent
    .post('/api/notes')
    .set('Authorization', `Bearer ${owner.accessToken}`)
    .set('X-CSRF-Token', owner.csrf)
    .send({ title: sqli, content: 'Nota secreta de owner' });
  assert.equal(created.status, 201);
  assert.equal(created.body.title, sqli);

  const noteId = created.body.id;

  // Other user cannot read, update, or delete owner's note -> 404
  assert.equal(
    (await other.agent.get(`/api/notes/${noteId}`).set('Authorization', `Bearer ${other.accessToken}`)).status,
    404
  );
  assert.equal(
    (await other.agent.patch(`/api/notes/${noteId}`).set('Authorization', `Bearer ${other.accessToken}`).set('X-CSRF-Token', other.csrf).send({ content: 'hack' })).status,
    404
  );
  assert.equal(
    (await other.agent.delete(`/api/notes/${noteId}`).set('Authorization', `Bearer ${other.accessToken}`).set('X-CSRF-Token', other.csrf)).status,
    404
  );

  // Owner updates and deletes note
  const updated = await owner.agent
    .patch(`/api/notes/${noteId}`)
    .set('Authorization', `Bearer ${owner.accessToken}`)
    .set('X-CSRF-Token', owner.csrf)
    .send({ title: 'Actualizada', content: 'Contenido actualizado' });
  assert.equal(updated.status, 200);
  assert.equal(updated.body.title, 'Actualizada');

  const del = await owner.agent
    .delete(`/api/notes/${noteId}`)
    .set('Authorization', `Bearer ${owner.accessToken}`)
    .set('X-CSRF-Token', owner.csrf);
  assert.equal(del.status, 204);
});

test('RBAC admin routes (403 for user, 200 for admin) and sanitized user/audit data', async () => {
  await registerAndVerify('normal@example.test');
  const adminPasswordHash = await hashPassword('Admin Super Secret Phrase 2026!');
  await pool.query(
    `insert into app_private.users (email, password_hash, role, status, email_verified_at)
     values ($1, $2, 'admin', 'active', now())`,
    ['admin@example.test', adminPasswordHash]
  );

  const normal = await loginAgent('normal@example.test', 'Correct Horse Battery Staple 2026!');
  assert.equal((await normal.agent.get('/api/admin/users').set('Authorization', `Bearer ${normal.accessToken}`)).status, 403);
  assert.equal((await normal.agent.get('/api/admin/audit').set('Authorization', `Bearer ${normal.accessToken}`)).status, 403);

  const admin = await loginAgent('admin@example.test', 'Admin Super Secret Phrase 2026!');
  const usersRes = await admin.agent.get('/api/admin/users').set('Authorization', `Bearer ${admin.accessToken}`);
  assert.equal(usersRes.status, 200);
  assert.equal(usersRes.body.some((u) => 'password_hash' in u), false);

  const normalUser = usersRes.body.find((u) => u.email === 'normal@example.test');
  const disableRes = await admin.agent
    .patch(`/api/admin/users/${normalUser.id}`)
    .set('Authorization', `Bearer ${admin.accessToken}`)
    .set('X-CSRF-Token', admin.csrf)
    .send({ status: 'disabled' });
  assert.equal(disableRes.status, 200);
  assert.equal(disableRes.body.status, 'disabled');

  // Self-disable blocked
  const selfDisable = await admin.agent
    .patch(`/api/admin/users/${admin.user.id}`)
    .set('Authorization', `Bearer ${admin.accessToken}`)
    .set('X-CSRF-Token', admin.csrf)
    .send({ status: 'disabled' });
  assert.equal(selfDisable.status, 400);

  const auditRes = await admin.agent.get('/api/admin/audit').set('Authorization', `Bearer ${admin.accessToken}`);
  assert.equal(auditRes.status, 200);
  assert.ok(auditRes.body.some((entry) => entry.eventType === 'ADMIN_USER_UPDATED'));
});

test('MFA TOTP setup (AES-256-GCM), login challenge, single-use recovery code, and reauthentication', async () => {
  await registerAndVerify('mfa@example.test');
  const session = await loginAgent('mfa@example.test', 'Correct Horse Battery Staple 2026!');

  // Setup fails with wrong password
  const badSetup = await session.agent
    .post('/api/mfa/setup')
    .set('Authorization', `Bearer ${session.accessToken}`)
    .set('X-CSRF-Token', session.csrf)
    .send({ currentPassword: 'wrong-password' });
  assert.equal(badSetup.status, 401);

  const setup = await session.agent
    .post('/api/mfa/setup')
    .set('Authorization', `Bearer ${session.accessToken}`)
    .set('X-CSRF-Token', session.csrf)
    .send({ currentPassword: 'Correct Horse Battery Staple 2026!' });
  assert.equal(setup.status, 200);
  assert.ok(setup.body.secret);
  assert.match(setup.body.otpauthUri, /^otpauth:\/\/totp\//);

  // Confirm DB stores encrypted JSON, never plaintext secret
  const dbMfa = await pool.query('select encrypted_secret from app_private.mfa_settings where user_id = $1', [session.user.id]);
  assert.equal(dbMfa.rows[0].encrypted_secret.alg, 'aes-256-gcm');
  assert.equal(JSON.stringify(dbMfa.rows[0].encrypted_secret).includes(setup.body.secret), false);

  const totpCode = generateTotpCode(setup.body.secret);
  const verifySetup = await session.agent
    .post('/api/mfa/verify-setup')
    .set('Authorization', `Bearer ${session.accessToken}`)
    .set('X-CSRF-Token', session.csrf)
    .send({ code: totpCode });
  assert.equal(verifySetup.status, 200);
  assert.equal(verifySetup.body.enabled, true);
  assert.equal(verifySetup.body.recoveryCodes.length, 8);

  // Login now issues challengeToken instead of session
  const challengeRes = await request(app).post('/api/auth/login').send({
    email: 'mfa@example.test',
    password: 'Correct Horse Battery Staple 2026!'
  });
  assert.equal(challengeRes.status, 200);
  assert.equal(challengeRes.body.mfaRequired, true);
  assert.ok(challengeRes.body.challengeToken);
  assert.equal(challengeRes.body.accessToken, undefined);

  // Challenge token cannot access protected routes
  assert.equal(
    (await request(app).get('/api/me').set('Authorization', `Bearer ${challengeRes.body.challengeToken}`)).status,
    401
  );

  // Complete login with recovery code
  const recoveryCode = verifySetup.body.recoveryCodes[0];
  const mfaLogin = await request(app).post('/api/auth/mfa/verify-login').send({
    challengeToken: challengeRes.body.challengeToken,
    recoveryCode
  });
  assert.equal(mfaLogin.status, 200);
  assert.ok(mfaLogin.body.accessToken);

  // Replaying same challenge token fails
  const replayChallenge = await request(app).post('/api/auth/mfa/verify-login').send({
    challengeToken: challengeRes.body.challengeToken,
    code: generateTotpCode(setup.body.secret)
  });
  assert.equal(replayChallenge.status, 401);

  // Reusing same recovery code fails
  const challenge2 = await request(app).post('/api/auth/login').send({
    email: 'mfa@example.test',
    password: 'Correct Horse Battery Staple 2026!'
  });
  const reuseRecovery = await request(app).post('/api/auth/mfa/verify-login').send({
    challengeToken: challenge2.body.challengeToken,
    recoveryCode
  });
  assert.equal(reuseRecovery.status, 401);

  // Valid TOTP completes login
  const totpLogin = await request(app).post('/api/auth/mfa/verify-login').send({
    challengeToken: challenge2.body.challengeToken,
    code: generateTotpCode(setup.body.secret)
  });
  assert.equal(totpLogin.status, 200);

  // Disable MFA requires password + valid code
  const disableCsrf = extractCookie(totpLogin.headers['set-cookie'], 'csrf');
  const disable = await request(app)
    .post('/api/mfa/disable')
    .set('Authorization', `Bearer ${totpLogin.body.accessToken}`)
    .set('Cookie', [`csrf=${disableCsrf}`])
    .set('X-CSRF-Token', disableCsrf)
    .send({
      currentPassword: 'Correct Horse Battery Staple 2026!',
      code: generateTotpCode(setup.body.secret)
    });
  assert.equal(disable.status, 200);
  assert.equal(disable.body.enabled, false);
});

test('sessions listing/revocation, password change, and password reset lifecycle', async () => {
  await registerAndVerify('reset@example.test');
  const s1 = await loginAgent('reset@example.test', 'Correct Horse Battery Staple 2026!');
  const s2 = await loginAgent('reset@example.test', 'Correct Horse Battery Staple 2026!');

  const list = await s1.agent.get('/api/sessions').set('Authorization', `Bearer ${s1.accessToken}`);
  assert.equal(list.status, 200);
  assert.equal(list.body.length, 2);
  assert.equal(list.body.filter((s) => s.isCurrent).length, 1);

  const revokeOthers = await s1.agent
    .post('/api/sessions/revoke-others')
    .set('Authorization', `Bearer ${s1.accessToken}`)
    .set('X-CSRF-Token', s1.csrf);
  assert.equal(revokeOthers.status, 200);
  assert.equal(await s2.agent.get('/api/me').set('Authorization', `Bearer ${s2.accessToken}`).then((r) => r.status), 401);

  const forgot = await request(app).post('/api/auth/forgot-password').send({ email: 'reset@example.test' });
  assert.equal(forgot.status, 202);
  const resetMail = sentEmails.filter((item) => item.type === 'reset').at(-1);
  assert.ok(resetMail?.token);

  // Expired reset token rejected
  await pool.query("update app_private.password_reset_tokens set expires_at = now() - interval '1 minute'");
  assert.equal(
    (await request(app).post('/api/auth/reset-password').send({
      token: resetMail.token,
      newPassword: 'Brand New Secure Password 2026!'
    })).status,
    400
  );

  // Valid reset token updates password, revokes active sessions, and is single-use
  await pool.query("update app_private.password_reset_tokens set expires_at = now() + interval '1 hour'");
  const resetOk = await request(app).post('/api/auth/reset-password').send({
    token: resetMail.token,
    newPassword: 'Brand New Secure Password 2026!'
  });
  assert.equal(resetOk.status, 200);

  // Previous session s1 revoked by password reset
  assert.equal((await s1.agent.get('/api/me').set('Authorization', `Bearer ${s1.accessToken}`)).status, 401);
  // Single-use reset token rejected on second attempt
  assert.equal(
    (await request(app).post('/api/auth/reset-password').send({
      token: resetMail.token,
      newPassword: 'Another New Password 2026!'
    })).status,
    400
  );
  // Old password rejected, new password works
  assert.equal(
    (await request(app).post('/api/auth/login').send({
      email: 'reset@example.test',
      password: 'Correct Horse Battery Staple 2026!'
    })).status,
    401
  );
  const s3 = await loginAgent('reset@example.test', 'Brand New Secure Password 2026!');
  assert.equal(s3.user.email, 'reset@example.test');
});
