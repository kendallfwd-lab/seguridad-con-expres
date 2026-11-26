import React, { useEffect, useState } from 'react';

export function AdminView({ mode, busy, users, auditLogs, currentUserId, onLoadUsers, onUpdateUser, onLoadAudit }) {
  const [statusFilter, setStatusFilter] = useState('');
  const [eventFilter, setEventFilter] = useState('');

  useEffect(() => {
    if (mode === 'users') onLoadUsers(statusFilter);
    else onLoadAudit(eventFilter);
  }, [mode]);

  if (mode === 'users') {
    return (
      <section className="card wide">
        <div className="row-between">
          <div>
            <h2>Administración de usuarios (RBAC)</h2>
            <p className="muted">Ruta administrativa protegida. Nunca expone hashes Argon2id ni secretos MFA.</p>
          </div>
          <div className="actions">
            <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); onLoadUsers(e.target.value); }}>
              <option value="">Todos los estados</option>
              <option value="active">active</option>
              <option value="pending_verification">pending_verification</option>
              <option value="disabled">disabled</option>
            </select>
            <button type="button" className="secondary" disabled={busy} onClick={() => onLoadUsers(statusFilter)}>Recargar</button>
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Correo</th>
                <th>Rol</th>
                <th>Estado</th>
                <th>MFA</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td>{u.email}</td>
                  <td><span className="pill">{u.role}</span></td>
                  <td>{u.status}</td>
                  <td>{u.mfaEnabled ? 'Sí' : 'No'}</td>
                  <td className="actions">
                    {u.id !== currentUserId && (
                      <>
                        {u.status !== 'active' && (
                          <button type="button" className="secondary" disabled={busy} onClick={() => onUpdateUser(u.id, { status: 'active' })}>
                            Activar
                          </button>
                        )}
                        {u.status !== 'disabled' && (
                          <button type="button" className="danger" disabled={busy} onClick={() => onUpdateUser(u.id, { status: 'disabled' })}>
                            Deshabilitar
                          </button>
                        )}
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    );
  }

  return (
    <section className="card wide">
      <div className="row-between">
        <div>
          <h2>Auditoría de seguridad</h2>
          <p className="muted">Eventos persistidos en `app_private.audit_log` sin credenciales ni secretos.</p>
        </div>
        <form className="actions" onSubmit={(e) => { e.preventDefault(); onLoadAudit(eventFilter); }}>
          <input
            value={eventFilter}
            onChange={(e) => setEventFilter(e.target.value)}
            placeholder="Filtrar event_type (ej. LOGIN_FAILED)"
          />
          <button type="submit" className="secondary" disabled={busy}>Filtrar</button>
        </form>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Evento</th>
              <th>Usuario</th>
              <th>IP</th>
              <th>Metadata</th>
              <th>Fecha</th>
            </tr>
          </thead>
          <tbody>
            {auditLogs.map((row) => (
              <tr key={row.id}>
                <td className="mono">{row.id}</td>
                <td><span className="pill">{row.eventType}</span></td>
                <td className="mono">{row.userId ? `${row.userId.slice(0, 8)}…` : 'anónimo'}</td>
                <td className="mono">{row.ipAddress || '-'}</td>
                <td className="mono">{JSON.stringify(row.metadata)}</td>
                <td>{new Date(row.createdAt).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
