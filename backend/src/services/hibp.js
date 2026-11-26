import crypto from 'node:crypto';

const LOCAL_COMPROMISED_PASSWORDS = new Set([
  'password123456789',
  '123456789012345',
  '1234567890123456',
  'qwertyuiopasdfgh',
  'qwertyuiop123456',
  'contrasena123456',
  'admin12345678901',
  'letmein123456789',
  'welcome123456789',
  'aaaaaaaaaaaaaaa'
]);

function hasLowEntropyPattern(password) {
  const normalized = password.toLowerCase();
  if (LOCAL_COMPROMISED_PASSWORDS.has(normalized)) return true;
  // Reject strings made of a single repeated character (e.g. "xxxxxxxxxxxxxxx")
  if (/^(.)\1+$/.test(normalized)) return true;
  return false;
}

/**
 * Checks whether a password is compromised using:
 * 1. Local blocklist + trivial repetition check.
 * 2. Have I Been Pwned Pwned Passwords Range API (k-anonymity: only first 5 SHA-1 hex chars sent).
 *
 * Documented failure policy: fail-open on external HIBP network timeout/error so registration/reset
 * remains available while still enforcing local blocklist and 15+ char minimum length.
 */
export async function checkCompromisedPassword(password, { enabled = true, fetchImpl = fetch, timeoutMs = 2500 } = {}) {
  if (hasLowEntropyPattern(password)) {
    return { compromised: true, source: 'local_blocklist', degraded: false };
  }

  if (!enabled) {
    return { compromised: false, source: 'disabled', degraded: false };
  }

  const sha1 = crypto.createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: {
        'Add-Padding': 'true',
        'User-Agent': 'Security-Lab-Express/1.0'
      },
      signal: controller.signal
    });
    if (!response.ok) {
      return { compromised: false, source: 'hibp_unavailable', degraded: true };
    }
    const body = await response.text();
    const lines = body.split(/\r?\n/);
    for (const line of lines) {
      const [candidateSuffix, countText] = line.split(':');
      if (candidateSuffix?.trim().toUpperCase() === suffix && Number(countText) > 0) {
        return { compromised: true, source: 'hibp_k_anonymity', degraded: false };
      }
    }
    return { compromised: false, source: 'hibp_k_anonymity', degraded: false };
  } catch {
    return { compromised: false, source: 'hibp_unavailable', degraded: true };
  } finally {
    clearTimeout(timer);
  }
}
