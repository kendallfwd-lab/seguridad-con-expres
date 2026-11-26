import React, { useState } from 'react';

export function AuthViews({
  route,
  navigate,
  busy,
  initialToken,
  onLogin,
  onVerifyMfaLogin,
  onRegister,
  onVerifyEmail,
  onResendVerification,
  onForgotPassword,
  onResetPassword,
  mfaChallenge
}) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [tokenInput, setTokenInput] = useState(initialToken || '');
  const [newPassword, setNewPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [feedback, setFeedback] = useState(null);

  async function handleSubmit(fn) {
    setFeedback(null);
    const res = await fn();
    if (res?.message) setFeedback(res);
  }

  if (mfaChallenge) {
    return (
      <section className="card">
        <h2>Verificación MFA requerida</h2>
        <p className="muted">Ingresa el código TOTP de 6 dígitos o uno de tus códigos de respaldo de un solo uso.</p>
        {feedback && <p className={`alert ${feedback.ok ? 'ok' : 'err'}`}>{feedback.message}</p>}
        <form onSubmit={(e) => {
          e.preventDefault();
          handleSubmit(async () => {
            const ok = await onVerifyMfaLogin(
              useRecovery ? { recoveryCode: mfaCode } : { code: mfaCode }
            );
            setMfaCode('');
            return ok ? null : { ok: false, message: 'Código MFA inválido o vencido.' };
          });
        }}>
          <label>
            {useRecovery ? 'Código de respaldo (XXXX-XXXX-XXXX)' : 'Código TOTP (6 dígitos)'}
            <input
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value)}
              placeholder={useRecovery ? 'A1B2-C3D4-E5F6' : '123456'}
              required
              autoFocus
            />
          </label>
          <div className="actions">
            <button disabled={busy}>{busy ? 'Verificando...' : 'Confirmar acceso'}</button>
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => { setUseRecovery((v) => !v); setMfaCode(''); }}
            >
              {useRecovery ? 'Usar código TOTP' : 'Usar código de respaldo'}
            </button>
          </div>
        </form>
      </section>
    );
  }

  if (route === '/register') {
    return (
      <section className="card">
        <h2>Crear cuenta</h2>
        <p className="muted">Contraseña mínima de 15 caracteres (hasta 128). Se verifica contra filtraciones conocidas.</p>
        {feedback && <p className={`alert ${feedback.ok ? 'ok' : 'err'}`}>{feedback.message}</p>}
        <form onSubmit={(e) => {
          e.preventDefault();
          handleSubmit(async () => {
            const r = await onRegister(email, password);
            setPassword('');
            return { ok: r.ok, message: r.data?.message || r.data?.error || 'Error al registrar' };
          });
        }}>
          <label>
            Correo electrónico
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </label>
          <label>
            Contraseña (mínimo 15 caracteres)
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              minLength={15}
              maxLength={128}
              autoComplete="new-password"
              required
            />
          </label>
          <div className="actions">
            <button disabled={busy}>{busy ? 'Registrando...' : 'Registrarme'}</button>
            <button type="button" className="secondary" onClick={() => navigate('/login')}>
              Ya tengo cuenta
            </button>
          </div>
        </form>
      </section>
    );
  }

  if (route === '/verify-email') {
    return (
      <section className="card">
        <h2>Verificar correo electrónico</h2>
        <p className="muted">Activa tu cuenta con el token de verificación o solicita uno nuevo.</p>
        {feedback && <p className={`alert ${feedback.ok ? 'ok' : 'err'}`}>{feedback.message}</p>}
        <form onSubmit={(e) => {
          e.preventDefault();
          handleSubmit(async () => {
            const r = await onVerifyEmail(tokenInput);
            return { ok: r.ok, message: r.data?.message || r.data?.error };
          });
        }}>
          <label>
            Token de verificación
            <input value={tokenInput} onChange={(e) => setTokenInput(e.target.value)} required />
          </label>
          <button disabled={busy}>{busy ? 'Verificando...' : 'Verificar cuenta'}</button>
        </form>
        <hr />
        <form onSubmit={(e) => {
          e.preventDefault();
          handleSubmit(async () => {
            const r = await onResendVerification(email);
            return { ok: r.ok, message: r.data?.message || r.data?.error };
          });
        }}>
          <label>
            Reenviar correo de verificación
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="correo@ejemplo.com" required />
          </label>
          <button type="submit" className="secondary" disabled={busy}>Reenviar token</button>
        </form>
      </section>
    );
  }

  if (route === '/forgot-password') {
    return (
      <section className="card">
        <h2>Recuperar contraseña</h2>
        <p className="muted">Solicita un token de restablecimiento de un solo uso válido por 1 hora.</p>
        {feedback && <p className={`alert ${feedback.ok ? 'ok' : 'err'}`}>{feedback.message}</p>}
        <form onSubmit={(e) => {
          e.preventDefault();
          handleSubmit(async () => {
            const r = await onForgotPassword(email);
            return { ok: r.ok, message: r.data?.message || r.data?.error };
          });
        }}>
          <label>
            Correo electrónico
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </label>
          <div className="actions">
            <button disabled={busy}>{busy ? 'Enviando...' : 'Solicitar recuperación'}</button>
            <button type="button" className="secondary" onClick={() => navigate('/reset-password')}>
              Ya tengo un token
            </button>
          </div>
        </form>
      </section>
    );
  }

  if (route === '/reset-password') {
    return (
      <section className="card">
        <h2>Restablecer contraseña</h2>
        <p className="muted">Al restablecer tu contraseña se revocan todas las sesiones activas anteriores.</p>
        {feedback && <p className={`alert ${feedback.ok ? 'ok' : 'err'}`}>{feedback.message}</p>}
        <form onSubmit={(e) => {
          e.preventDefault();
          handleSubmit(async () => {
            const r = await onResetPassword(tokenInput, newPassword);
            setNewPassword('');
            return { ok: r.ok, message: r.data?.message || r.data?.error };
          });
        }}>
          <label>
            Token de recuperación
            <input value={tokenInput} onChange={(e) => setTokenInput(e.target.value)} required />
          </label>
          <label>
            Nueva contraseña (mínimo 15 caracteres)
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              minLength={15}
              maxLength={128}
              autoComplete="new-password"
              required
            />
          </label>
          <div className="actions">
            <button disabled={busy}>{busy ? 'Actualizando...' : 'Cambiar contraseña'}</button>
            <button type="button" className="secondary" onClick={() => navigate('/login')}>
              Volver al login
            </button>
          </div>
        </form>
      </section>
    );
  }

  return (
    <section className="card">
      <h2>Iniciar sesión</h2>
      <p className="muted">Autenticación con Argon2id, JWT en memoria y refresh token rotado en cookie HttpOnly.</p>
      {feedback && <p className={`alert ${feedback.ok ? 'ok' : 'err'}`}>{feedback.message}</p>}
      <form onSubmit={(e) => {
        e.preventDefault();
        handleSubmit(async () => {
          const r = await onLogin(email, password);
          setPassword('');
          if (!r.ok) return { ok: false, message: r.data?.error || 'Error al iniciar sesión' };
          return null;
        });
      }}>
        <label>
          Correo electrónico
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </label>
        <label>
          Contraseña
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            maxLength={128}
            autoComplete="current-password"
            required
          />
        </label>
        <div className="actions">
          <button disabled={busy}>{busy ? 'Ingresando...' : 'Ingresar'}</button>
          <button type="button" className="secondary" onClick={() => navigate('/register')}>
            Crear cuenta
          </button>
          <button type="button" className="secondary" onClick={() => navigate('/forgot-password')}>
            Olvidé mi contraseña
          </button>
          <button type="button" className="secondary" onClick={() => navigate('/verify-email')}>
            Verificar correo
          </button>
        </div>
      </form>
    </section>
  );
}
