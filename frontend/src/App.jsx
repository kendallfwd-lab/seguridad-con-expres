import React, { useEffect, useState } from 'react';
import {
  apiRequest,
  clearAccessToken,
  refreshSessionSingleFlight,
  setAccessToken
} from './api/client.js';
import { AuthViews } from './components/AuthViews.jsx';
import { NotesView } from './components/NotesView.jsx';
import { ProfileSecurityView } from './components/ProfileSecurityView.jsx';
import { AdminView } from './components/AdminView.jsx';
import { SecurityLabView } from './components/SecurityLabView.jsx';
import { InspectorPanel } from './components/InspectorPanel.jsx';

const PUBLIC_AUTH_ROUTES = new Set(['/login', '/register', '/verify-email', '/forgot-password', '/reset-password']);

function resolveInitialState() {
  const params = new URLSearchParams(window.location.search);
  const action = params.get('action');
  const token = params.get('token') || '';
  if (action === 'verify-email') return { path: '/verify-email', token };
  if (action === 'reset-password') return { path: '/reset-password', token };
  const path = window.location.pathname === '/' ? '/login' : window.location.pathname;
  return { path, token: '' };
}

export function App() {
  const initial = resolveInitialState();
  const [route, setRoute] = useState(initial.path);
  const [urlToken] = useState(initial.token);
  const [user, setUser] = useState(null);
  const [mfaChallenge, setMfaChallenge] = useState(null);
  const [mfaStatus, setMfaStatus] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [notes, setNotes] = useState([]);
  const [adminUsers, setAdminUsers] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [history, setHistory] = useState([]);
  const [selectedInspect, setSelectedInspect] = useState(null);
  const [busy, setBusy] = useState(false);
  const [booting, setBooting] = useState(true);

  function addInspect(entry) {
    setHistory((prev) => [entry, ...prev].slice(0, 25));
    setSelectedInspect(entry);
  }

  function navigate(path) {
    setRoute(path);
    if (window.location.pathname !== path) {
      window.history.pushState({}, '', path);
    }
  }

  function resetSessionState() {
    clearAccessToken();
    setUser(null);
    setMfaChallenge(null);
    setMfaStatus(null);
    setSessions([]);
    setNotes([]);
    setAdminUsers([]);
    setAuditLogs([]);
  }

  async function withBusy(fn) {
    setBusy(true);
    try {
      return await fn();
    } catch (error) {
      addInspect({
        id: crypto.randomUUID(),
        method: 'CLIENT',
        path: 'network',
        status: 0,
        durationMs: 0,
        requestBody: null,
        data: { error: error.message }
      });
      return { ok: false, status: 0, data: { error: 'Error de conexión' } };
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    const onPop = () => setRoute(window.location.pathname === '/' ? '/login' : window.location.pathname);
    window.addEventListener('popstate', onPop);

    (async () => {
      try {
        await fetch('/api/csrf', { credentials: 'same-origin' });
        const restored = await refreshSessionSingleFlight();
        if (restored?.user) {
          setUser(restored.user);
          if (PUBLIC_AUTH_ROUTES.has(window.location.pathname) || window.location.pathname === '/') {
            navigate('/notes');
          }
        }
      } catch {
        // Ignore offline boot error
      } finally {
        setBooting(false);
      }
    })();

    return () => window.removeEventListener('popstate', onPop);
  }, []);

  const callApi = (path, opts = {}) =>
    apiRequest(path, { ...opts, onInspect: addInspect, onSessionLost: resetSessionState });

  async function handleLogin(email, password) {
    return withBusy(async () => {
      const r = await callApi('/auth/login', { method: 'POST', body: { email, password }, tokenOverride: '' });
      if (r.ok && r.data?.mfaRequired) {
        setMfaChallenge(r.data.challengeToken);
        return r;
      }
      if (r.ok && r.data?.accessToken) {
        setAccessToken(r.data.accessToken);
        setUser(r.data.user);
        setMfaChallenge(null);
        navigate('/notes');
      }
      return r;
    });
  }

  async function handleVerifyMfaLogin(payload) {
    return withBusy(async () => {
      const r = await callApi('/auth/mfa/verify-login', {
        method: 'POST',
        body: { challengeToken: mfaChallenge, ...payload },
        tokenOverride: ''
      });
      if (r.ok && r.data?.accessToken) {
        setAccessToken(r.data.accessToken);
        setUser(r.data.user);
        setMfaChallenge(null);
        navigate('/notes');
        return true;
      }
      return false;
    });
  }

  async function handleLogout() {
    await withBusy(async () => {
      await callApi('/auth/logout', { method: 'POST' });
      resetSessionState();
      navigate('/login');
    });
  }

  async function loadNotes() {
    return withBusy(async () => {
      const r = await callApi('/notes');
      if (r.ok && Array.isArray(r.data)) setNotes(r.data);
      return r;
    });
  }

  async function loadProfile() {
    return withBusy(async () => {
      const r = await callApi('/me');
      if (r.ok && r.data) setUser(r.data);
      return r;
    });
  }

  async function loadMfaStatus() {
    return withBusy(async () => {
      const r = await callApi('/mfa/status');
      if (r.ok) setMfaStatus(r.data);
      return r;
    });
  }

  async function loadSessions() {
    return withBusy(async () => {
      const r = await callApi('/sessions');
      if (r.ok && Array.isArray(r.data)) setSessions(r.data);
      return r;
    });
  }

  const isPrivateRoute = ['/notes', '/profile'].includes(route);
  const isAdminRoute = ['/admin/users', '/admin/audit'].includes(route);

  function renderMainContent() {
    if (booting) {
      return <section className="card"><p>Iniciando sesión segura...</p></section>;
    }

    if (isAdminRoute) {
      if (!user) {
        return (
          <section className="card">
            <h2>Autenticación requerida (401)</h2>
            <p className="muted">Inicia sesión con una cuenta administrativa para acceder a esta sección.</p>
            <button type="button" onClick={() => navigate('/login')}>Ir a iniciar sesión</button>
          </section>
        );
      }
      if (user.role !== 'admin') {
        return (
          <section className="card">
            <h2>Acceso denegado · 403</h2>
            <p className="alert err">Esta ruta requiere rol `admin`. Tu rol actual es `{user.role}`.</p>
            <button type="button" className="secondary" onClick={() => navigate('/notes')}>Volver a mis notas</button>
          </section>
        );
      }
      return (
        <AdminView
          mode={route === '/admin/users' ? 'users' : 'audit'}
          busy={busy}
          users={adminUsers}
          auditLogs={auditLogs}
          currentUserId={user.id}
          onLoadUsers={(status) => withBusy(async () => {
            const q = status ? `?status=${encodeURIComponent(status)}` : '';
            const r = await callApi(`/admin/users${q}`);
            if (r.ok && Array.isArray(r.data)) setAdminUsers(r.data);
          })}
          onUpdateUser={(id, changes) => withBusy(async () => {
            const r = await callApi(`/admin/users/${id}`, { method: 'PATCH', body: changes });
            if (r.ok) {
              setAdminUsers((prev) => prev.map((u) => (u.id === id ? { ...u, ...r.data } : u)));
            }
          })}
          onLoadAudit={(eventType) => withBusy(async () => {
            const q = eventType ? `?eventType=${encodeURIComponent(eventType)}` : '';
            const r = await callApi(`/admin/audit${q}`);
            if (r.ok && Array.isArray(r.data)) setAuditLogs(r.data);
          })}
        />
      );
    }

    if (route === '/lab') {
      return (
        <SecurityLabView
          busy={busy}
          user={user}
          onProbe={(path, method = 'GET', body, tokenOverride, omitCsrf = false) =>
            withBusy(() => callApi(path, { method, body, tokenOverride, omitCsrf, skipAutoRefresh: true }))
          }
          onConcurrentRefresh={() =>
            withBusy(async () => {
              const [a, b] = await Promise.all([
                refreshSessionSingleFlight(addInspect),
                refreshSessionSingleFlight(addInspect)
              ]);
              if (a?.user) setUser(a.user);
              else if (b?.user) setUser(b.user);
              else resetSessionState();
            })
          }
        />
      );
    }

    if (isPrivateRoute && !user) {
      return (
        <AuthViews
          route="/login"
          navigate={navigate}
          busy={busy}
          initialToken={urlToken}
          mfaChallenge={mfaChallenge}
          onLogin={handleLogin}
          onVerifyMfaLogin={handleVerifyMfaLogin}
          onRegister={(email, password) => withBusy(() => callApi('/auth/register', { method: 'POST', body: { email, password }, tokenOverride: '' }))}
          onVerifyEmail={(token) => withBusy(() => callApi('/auth/verify-email', { method: 'POST', body: { token }, tokenOverride: '' }))}
          onResendVerification={(email) => withBusy(() => callApi('/auth/resend-verification', { method: 'POST', body: { email }, tokenOverride: '' }))}
          onForgotPassword={(email) => withBusy(() => callApi('/auth/forgot-password', { method: 'POST', body: { email }, tokenOverride: '' }))}
          onResetPassword={(token, newPassword) => withBusy(() => callApi('/auth/reset-password', { method: 'POST', body: { token, newPassword }, tokenOverride: '' }))}
        />
      );
    }

    if (route === '/notes' && user) {
      return (
        <NotesView
          busy={busy}
          notes={notes}
          onLoadNotes={loadNotes}
          onCreateNote={(title, content) => withBusy(async () => {
            const r = await callApi('/notes', { method: 'POST', body: { title, content } });
            if (r.ok) setNotes((prev) => [r.data, ...prev]);
            return r;
          })}
          onUpdateNote={(id, title, content) => withBusy(async () => {
            const r = await callApi(`/notes/${id}`, { method: 'PATCH', body: { title, content } });
            if (r.ok) setNotes((prev) => prev.map((n) => (n.id === id ? r.data : n)));
            return r;
          })}
          onDeleteNote={(id) => withBusy(async () => {
            const r = await callApi(`/notes/${id}`, { method: 'DELETE' });
            if (r.ok) setNotes((prev) => prev.filter((n) => n.id !== id));
            return r;
          })}
          onProbeOwnership={(method, id) => withBusy(() => callApi(`/notes/${encodeURIComponent(id)}`, { method }))}
        />
      );
    }

    if (route === '/profile' && user) {
      return (
        <ProfileSecurityView
          busy={busy}
          user={user}
          mfaStatus={mfaStatus}
          sessions={sessions}
          onLoadProfile={loadProfile}
          onLoadMfaStatus={loadMfaStatus}
          onLoadSessions={loadSessions}
          onChangePassword={(currentPassword, newPassword) =>
            withBusy(() => callApi('/auth/change-password', { method: 'POST', body: { currentPassword, newPassword } }))
          }
          onStartMfaSetup={(currentPassword) =>
            withBusy(() => callApi('/mfa/setup', { method: 'POST', body: { currentPassword } }))
          }
          onVerifyMfaSetup={(code) =>
            withBusy(async () => {
              const r = await callApi('/mfa/verify-setup', { method: 'POST', body: { code } });
              if (r.ok) {
                await loadMfaStatus();
                await loadProfile();
              }
              return r;
            })
          }
          onRegenerateRecovery={(currentPassword) =>
            withBusy(async () => {
              const r = await callApi('/mfa/recovery-codes/regenerate', { method: 'POST', body: { currentPassword } });
              if (r.ok) await loadMfaStatus();
              return r;
            })
          }
          onDisableMfa={(currentPassword, code) =>
            withBusy(async () => {
              const r = await callApi('/mfa/disable', { method: 'POST', body: { currentPassword, code } });
              if (r.ok) {
                await loadMfaStatus();
                await loadProfile();
              }
              return r;
            })
          }
          onRevokeSession={(familyId) =>
            withBusy(async () => {
              const target = sessions.find((s) => s.familyId === familyId);
              const r = await callApi(`/sessions/${familyId}`, { method: 'DELETE' });
              if (r.ok) {
                if (target?.isCurrent) {
                  resetSessionState();
                  navigate('/login');
                } else {
                  setSessions((prev) => prev.filter((s) => s.familyId !== familyId));
                }
              }
            })
          }
          onRevokeOtherSessions={() =>
            withBusy(async () => {
              const r = await callApi('/sessions/revoke-others', { method: 'POST' });
              if (r.ok) await loadSessions();
            })
          }
        />
      );
    }

    return (
      <AuthViews
        route={PUBLIC_AUTH_ROUTES.has(route) ? route : '/login'}
        navigate={navigate}
        busy={busy}
        initialToken={urlToken}
        mfaChallenge={mfaChallenge}
        onLogin={handleLogin}
        onVerifyMfaLogin={handleVerifyMfaLogin}
        onRegister={(email, password) => withBusy(() => callApi('/auth/register', { method: 'POST', body: { email, password }, tokenOverride: '' }))}
        onVerifyEmail={(token) => withBusy(() => callApi('/auth/verify-email', { method: 'POST', body: { token }, tokenOverride: '' }))}
        onResendVerification={(email) => withBusy(() => callApi('/auth/resend-verification', { method: 'POST', body: { email }, tokenOverride: '' }))}
        onForgotPassword={(email) => withBusy(() => callApi('/auth/forgot-password', { method: 'POST', body: { email }, tokenOverride: '' }))}
        onResetPassword={(token, newPassword) => withBusy(() => callApi('/auth/reset-password', { method: 'POST', body: { token, newPassword }, tokenOverride: '' }))}
      />
    );
  }

  return (
    <main>
      <header className="topbar">
        <div className="brand-wrap">
          <div className="brand">SL</div>
          <div>
            <h1>Security Lab</h1>
            <p className="muted">Express + PostgreSQL + React · Seguridad completa</p>
          </div>
        </div>
        <div className="topbar-right">
          <span className="pill">{user ? `${user.email} (${user.role})` : 'Sin sesión'}</span>
          {user && (
            <button type="button" className="secondary" disabled={busy} onClick={handleLogout}>
              Cerrar sesión
            </button>
          )}
        </div>
      </header>

      <nav className="nav" aria-label="Navegación principal">
        {!user ? (
          <>
            <button type="button" className={route === '/login' ? '' : 'secondary'} onClick={() => navigate('/login')}>Login</button>
            <button type="button" className={route === '/register' ? '' : 'secondary'} onClick={() => navigate('/register')}>Registro</button>
            <button type="button" className={route === '/verify-email' ? '' : 'secondary'} onClick={() => navigate('/verify-email')}>Verificar correo</button>
            <button type="button" className={route === '/forgot-password' ? '' : 'secondary'} onClick={() => navigate('/forgot-password')}>Recuperar</button>
          </>
        ) : (
          <>
            <button type="button" className={route === '/notes' ? '' : 'secondary'} onClick={() => navigate('/notes')}>Notas</button>
            <button type="button" className={route === '/profile' ? '' : 'secondary'} onClick={() => navigate('/profile')}>Perfil, MFA y Sesiones</button>
            {user.role === 'admin' && (
              <>
                <button type="button" className={route === '/admin/users' ? '' : 'secondary'} onClick={() => navigate('/admin/users')}>Usuarios</button>
                <button type="button" className={route === '/admin/audit' ? '' : 'secondary'} onClick={() => navigate('/admin/audit')}>Auditoría</button>
              </>
            )}
          </>
        )}
        <button type="button" className={route === '/lab' ? '' : 'secondary'} onClick={() => navigate('/lab')}>Laboratorio HTTP</button>
      </nav>

      <div className="layout">
        {renderMainContent()}
        <InspectorPanel
          history={history}
          selected={selectedInspect}
          onSelect={setSelectedInspect}
          onClear={() => { setHistory([]); setSelectedInspect(null); }}
        />
      </div>
    </main>
  );
}
