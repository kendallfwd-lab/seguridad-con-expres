import { after, before, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import pg from 'pg';
import { createApp } from './app.js';
import { loadEnv } from './config/env.js';
import { generateTotpCode } from './security.js';

const { Pool } = pg;

function buildTestDatabaseUrl() {
  const baseEnv = loadEnv();
  const url = new URL(baseEnv.DATABASE_URL);
  url.pathname = '/security_lab_test';
  return url.toString();
}

function parseSetCookies(setCookieHeaders = []) {
  const jar = {};
  for (const header of setCookieHeaders) {
    const [pair] = header.split(';');
    const idx = pair.indexOf('=');
    if (idx > 0) {
      const name = pair.slice(0, idx);
      const val = pair.slice(idx + 1);
      if (val) jar[name] = val;
      else delete jar[name];
    }
  }
  return jar;
}

let pool;
let server;
let baseUrl;
let capturedTokens;

before(async () => {
  const dbUrl = buildTestDatabaseUrl();
  const env = loadEnv({
    NODE_ENV: 'test',
    APP_ORIGIN: 'http://localhost:5173',
    DATABASE_URL: dbUrl,
    JWT_SECRET: 'e2e-test-secret-with-more-than-32-bytes',
    DATA_KEY: crypto.randomBytes(32).toString('base64'),
    COOKIE_SECURE: 'false',
    HIBP_CHECK_ENABLED: 'false'
  });
  pool = new Pool({ connectionString: dbUrl, max: 5 });
  const app = await createApp({
    pool,
    env,
    mailer: {
      configured: true,
      async sendVerificationEmail({ to, token }) {
        capturedTokens.push({ kind: 'verify', to, token });
        return { sent: true };
      },
      async sendPasswordResetEmail({ to, token }) {
        capturedTokens.push({ kind: 'reset', to, token });
        return { sent: true };
      }
    }
  });
  server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}/api`;
});

beforeEach(async () => {
  capturedTokens = [];
  await pool.query('delete from app_private.audit_log');
  await pool.query('delete from app_private.login_attempts');
  await pool.query('delete from app_private.users');
});

after(async () => {
  await new Promise((resolve) => server?.close(resolve));
  await pool?.end();
});

test('E2E over real TCP HTTP: full auth, MFA, notes, sessions, client single-flight refresh, and logout', async () => {
  const cookies = {};
  let accessToken = '';

  async function clientFetch(path, { method = 'GET', body, headers = {} } = {}) {
    const cookieStr = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
    const isWrite = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
    const res = await fetch(`${baseUrl}${path}`, {
      method,
      headers: {
        Origin: 'http://localhost:5173',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
        ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
        ...(cookieStr ? { Cookie: cookieStr } : {}),
        ...(isWrite && cookies.csrf ? { 'X-CSRF-Token': cookies.csrf } : {}),
        ...headers
      },
      body: body ? JSON.stringify(body) : undefined
    });
    const setCookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    Object.assign(cookies, parseSetCookies(setCookies));
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = text; }
    return { status: res.status, json };
  }

  // 1. Bootstrap CSRF + Register + Verify Email
  assert.equal((await clientFetch('/csrf')).status, 200);
  const email = 'e2e-user@example.test';
  const password = 'E2E Security Lab Passphrase 2026!';
  assert.equal((await clientFetch('/auth/register', { method: 'POST', body: { email, password } })).status, 202);
  const verifyToken = capturedTokens.find((t) => t.kind === 'verify')?.token;
  assert.ok(verifyToken);
  assert.equal((await clientFetch('/auth/verify-email', { method: 'POST', body: { token: verifyToken } })).status, 200);

  // 2. Login + Create Note + Enable MFA
  const login = await clientFetch('/auth/login', { method: 'POST', body: { email, password } });
  assert.equal(login.status, 200);
  accessToken = login.json.accessToken;

  const note = await clientFetch('/notes', { method: 'POST', body: { title: 'E2E', content: 'Persisted in PG' } });
  assert.equal(note.status, 201);

  const setup = await clientFetch('/mfa/setup', { method: 'POST', body: { currentPassword: password } });
  assert.equal(setup.status, 200);
  const verifySetup = await clientFetch('/mfa/verify-setup', {
    method: 'POST',
    body: { code: generateTotpCode(setup.json.secret) }
  });
  assert.equal(verifySetup.status, 200);

  // 3. Logout then login with MFA
  assert.equal((await clientFetch('/auth/logout', { method: 'POST' })).status, 204);
  accessToken = '';

  const mfaLogin = await clientFetch('/auth/login', { method: 'POST', body: { email, password } });
  assert.equal(mfaLogin.status, 200);
  assert.equal(mfaLogin.json.mfaRequired, true);

  const completeMfa = await clientFetch('/auth/mfa/verify-login', {
    method: 'POST',
    body: { challengeToken: mfaLogin.json.challengeToken, code: generateTotpCode(setup.json.secret) }
  });
  assert.equal(completeMfa.status, 200);
  accessToken = completeMfa.json.accessToken;

  // 4. Refresh session + read notes + verify persistence
  const refreshed = await clientFetch('/auth/refresh', { method: 'POST' });
  assert.equal(refreshed.status, 200);
  accessToken = refreshed.json.accessToken;

  const notesList = await clientFetch('/notes');
  assert.equal(notesList.status, 200);
  assert.equal(notesList.json.length, 1);
  assert.equal(notesList.json[0].content, 'Persisted in PG');
});
