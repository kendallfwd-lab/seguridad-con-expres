let memoryAccessToken = '';
let inflightRefresh = null;

export function getAccessToken() {
  return memoryAccessToken;
}

export function setAccessToken(token) {
  memoryAccessToken = token || '';
}

export function clearAccessToken() {
  memoryAccessToken = '';
}

export function readCsrfCookie() {
  const match = document.cookie
    .split('; ')
    .find((entry) => entry.startsWith('csrf='));
  return match ? decodeURIComponent(match.slice(5)) : '';
}

export function sanitizeForInspector(value) {
  if (!value || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(sanitizeForInspector);
  const sensitiveKeys = new Set([
    'accessToken',
    'challengeToken',
    'secret',
    'otpauthUri',
    'recoveryCodes',
    'password',
    'currentPassword',
    'newPassword',
    'token'
  ]);
  const clone = {};
  for (const [k, v] of Object.entries(value)) {
    if (sensitiveKeys.has(k)) {
      clone[k] = Array.isArray(v) ? `[${v.length} códigos ocultos]` : '[oculto]';
    } else {
      clone[k] = sanitizeForInspector(v);
    }
  }
  return clone;
}

async function ensureCsrfToken() {
  let token = readCsrfCookie();
  if (!token) {
    const res = await fetch('/api/csrf', { credentials: 'same-origin' });
    if (res.ok) {
      const data = await res.json();
      token = data.csrfToken || readCsrfCookie();
    }
  }
  return token;
}

export async function refreshSessionSingleFlight(onInspect) {
  if (!inflightRefresh) {
    inflightRefresh = (async () => {
      const csrf = await ensureCsrfToken();
      const started = performance.now();
      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        credentials: 'same-origin',
        headers: csrf ? { 'X-CSRF-Token': csrf } : {}
      });
      const durationMs = Math.round(performance.now() - started);
      const raw = await response.text();
      let data;
      try {
        data = raw ? JSON.parse(raw) : null;
      } catch {
        data = raw;
      }
      onInspect?.({
        id: crypto.randomUUID(),
        method: 'POST',
        path: '/api/auth/refresh',
        status: response.status,
        durationMs,
        requestBody: null,
        data: sanitizeForInspector(data)
      });
      if (!response.ok) {
        clearAccessToken();
        return null;
      }
      setAccessToken(data.accessToken);
      return data;
    })().finally(() => {
      inflightRefresh = null;
    });
  }
  return inflightRefresh;
}

export async function apiRequest(
  path,
  { method = 'GET', body, tokenOverride, skipAutoRefresh = false, omitCsrf = false, onInspect, onSessionLost } = {}
) {
  const isMutation = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase());
  const csrf = isMutation && !omitCsrf ? await ensureCsrfToken() : '';

  const execute = async (bearer) => {
    const headers = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    if (isMutation && !omitCsrf && csrf) headers['X-CSRF-Token'] = csrf;

    const started = performance.now();
    const response = await fetch(`/api${path}`, {
      method,
      credentials: 'same-origin',
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined
    });
    const durationMs = Math.round(performance.now() - started);
    const raw = await response.text();
    let data;
    try {
      data = raw ? JSON.parse(raw) : null;
    } catch {
      data = raw;
    }

    onInspect?.({
      id: crypto.randomUUID(),
      method,
      path: `/api${path}`,
      status: response.status,
      durationMs,
      requestBody: body !== undefined ? sanitizeForInspector(body) : null,
      data: sanitizeForInspector(data)
    });

    return { ok: response.ok, status: response.status, data };
  };

  const initialBearer = tokenOverride !== undefined ? tokenOverride : getAccessToken();
  let result = await execute(initialBearer);

  if (
    result.status === 401 &&
    !skipAutoRefresh &&
    tokenOverride === undefined &&
    getAccessToken() &&
    !path.startsWith('/auth/')
  ) {
    const refreshed = await refreshSessionSingleFlight(onInspect);
    if (refreshed?.accessToken) {
      result = await execute(refreshed.accessToken);
    } else {
      onSessionLost?.();
    }
  }

  return result;
}
