import React, { useEffect, useState } from 'react';

export function ProfileSecurityView({
  busy,
  user,
  mfaStatus,
  sessions,
  onLoadProfile,
  onLoadMfaStatus,
  onLoadSessions,
  onChangePassword,
  onStartMfaSetup,
  onVerifyMfaSetup,
  onRegenerateRecovery,
  onDisableMfa,
  onRevokeSession,
  onRevokeOtherSessions
}) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [mfaPassword, setMfaPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [setupData, setSetupData] = useState(null);
  const [recoveryCodes, setRecoveryCodes] = useState(null);
  const [disableCode, setDisableCode] = useState('');
  const [feedback, setFeedback] = useState(null);

  useEffect(() => {
    onLoadProfile();
    onLoadMfaStatus();
    onLoadSessions();
  }, []);

  return (
    <div className="stack">
      <section className="card">
        <div className="row-between">
          <h2>Perfil de usuario</h2>
          <button type="button" className="secondary" disabled={busy} onClick={onLoadProfile}>Actualizar</button>
        </div>
        {feedback && <p className={`alert ${feedback.ok ? 'ok' : 'err'}`}>{feedback.message}</p>}
        <dl className="kv-grid">
          <dt>ID</dt><dd className="mono">{user.id}</dd>
          <dt>Correo</dt><dd>{user.email}</dd>
          <dt>Rol</dt><dd><span className="pill">{user.role}</span></dd>
          <dt>Estado</dt><dd>{user.status || 'active'}</dd>
          <dt>MFA TOTP</dt><dd>{mfaStatus?.enabled ? 'Activo' : 'Desactivado'}</dd>
          <dt>Códigos de respaldo</dt><dd>{mfaStatus?.remainingRecoveryCodes ?? 0} disponibles</dd>
        </dl>

        <h3>Cambiar contraseña (requiere reautenticación)</h3>
        <form onSubmit={async (e) => {
          e.preventDefault();
          setFeedback(null);
          const r = await onChangePassword(currentPassword, newPassword);
          setCurrentPassword('');
          setNewPassword('');
          setFeedback({ ok: r.ok, message: r.data?.message || r.data?.error });
        }}>
          <label>
            Contraseña actual
            <input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} required />
          </label>
          <label>
            Nueva contraseña (mínimo 15 caracteres)
            <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} minLength={15} maxLength={128} required />
          </label>
          <button disabled={busy}>Actualizar contraseña</button>
        </form>
      </section>

      <section className="card">
        <h2>Autenticación multifactor (MFA TOTP · AES-256-GCM)</h2>
        {!mfaStatus?.enabled ? (
          <>
            <form onSubmit={async (e) => {
              e.preventDefault();
              setFeedback(null);
              const r = await onStartMfaSetup(mfaPassword);
              setMfaPassword('');
              if (r.ok) {
                setSetupData(r.data);
                setRecoveryCodes(null);
              } else {
                setFeedback({ ok: false, message: r.data?.error || 'No se pudo iniciar MFA' });
              }
            }}>
              <label>
                Contraseña actual para iniciar configuración
                <input type="password" value={mfaPassword} onChange={(e) => setMfaPassword(e.target.value)} required />
              </label>
              <button disabled={busy}>Generar secreto TOTP</button>
            </form>

            {setupData && (
              <div className="box">
                <p><strong>Secreto Base32:</strong> <span className="mono">{setupData.secret}</span></p>
                <p className="muted">URI para app autenticadora:</p>
                <pre>{setupData.otpauthUri}</pre>
                <form onSubmit={async (e) => {
                  e.preventDefault();
                  const r = await onVerifyMfaSetup(totpCode);
                  setTotpCode('');
                  if (r.ok) {
                    setSetupData(null);
                    setRecoveryCodes(r.data.recoveryCodes);
                    setFeedback({ ok: true, message: 'MFA activado correctamente. Guarda tus códigos de respaldo.' });
                  } else {
                    setFeedback({ ok: false, message: r.data?.error || 'Código inválido' });
                  }
                }}>
                  <label>
                    Código TOTP de 6 dígitos
                    <input value={totpCode} onChange={(e) => setTotpCode(e.target.value)} required />
                  </label>
                  <button disabled={busy}>Activar MFA</button>
                </form>
              </div>
            )}
          </>
        ) : (
          <>
            <p className="muted">Tu cuenta está protegida con TOTP cifrado en servidor mediante AES-256-GCM.</p>
            <form onSubmit={async (e) => {
              e.preventDefault();
              const r = await onRegenerateRecovery(mfaPassword);
              setMfaPassword('');
              if (r.ok) {
                setRecoveryCodes(r.data.recoveryCodes);
                setFeedback({ ok: true, message: 'Códigos de respaldo regenerados.' });
              } else {
                setFeedback({ ok: false, message: r.data?.error });
              }
            }}>
              <label>
                Contraseña actual
                <input type="password" value={mfaPassword} onChange={(e) => setMfaPassword(e.target.value)} required />
              </label>
              <button type="submit" className="secondary" disabled={busy}>Regenerar códigos de respaldo</button>
            </form>

            <hr />
            <form onSubmit={async (e) => {
              e.preventDefault();
              const r = await onDisableMfa(mfaPassword, disableCode);
              setMfaPassword('');
              setDisableCode('');
              setRecoveryCodes(null);
              setFeedback({ ok: r.ok, message: r.ok ? 'MFA desactivado.' : r.data?.error });
            }}>
              <label>
                Código TOTP o de respaldo para desactivar MFA
                <input value={disableCode} onChange={(e) => setDisableCode(e.target.value)} required />
              </label>
              <button className="danger" disabled={busy || !mfaPassword}>Desactivar MFA</button>
            </form>
          </>
        )}

        {recoveryCodes && (
          <div className="box">
            <strong>Códigos de respaldo (se muestran una sola vez):</strong>
            <ul className="codes-grid mono">
              {recoveryCodes.map((code) => <li key={code}>{code}</li>)}
            </ul>
          </div>
        )}
      </section>

      <section className="card wide">
        <div className="row-between">
          <div>
            <h2>Administración de sesiones</h2>
            <p className="muted">Familias de refresh tokens activas para tu cuenta.</p>
          </div>
          <div className="actions">
            <button type="button" className="secondary" disabled={busy} onClick={onLoadSessions}>Actualizar</button>
            <button type="button" className="danger" disabled={busy} onClick={onRevokeOtherSessions}>Cerrar otras sesiones</button>
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Familia</th>
                <th>Inicio</th>
                <th>Última rotación</th>
                <th>Expira</th>
                <th>Rotaciones</th>
                <th>Acción</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.familyId}>
                  <td className="mono">{s.familyId.slice(0, 8)}… {s.isCurrent && <span className="badge ok">Actual</span>}</td>
                  <td>{new Date(s.startedAt).toLocaleString()}</td>
                  <td>{new Date(s.lastRotatedAt).toLocaleString()}</td>
                  <td>{new Date(s.expiresAt).toLocaleString()}</td>
                  <td>{s.rotations}</td>
                  <td>
                    <button type="button" className="secondary" disabled={busy} onClick={() => onRevokeSession(s.familyId)}>
                      Revocar
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
