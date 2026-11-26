import React from 'react';

export function SecurityLabView({ busy, user, onProbe, onConcurrentRefresh }) {
  return (
    <section className="card wide">
      <h2>Laboratorio interactivo de seguridad</h2>
      <p className="muted">
        Ejecuta casos reales contra la API Express + PostgreSQL y observa códigos HTTP 200, 201, 204, 400, 401, 403, 404 y 429 en el Inspector.
      </p>
      <div className="actions">
        <button type="button" className="secondary" disabled={busy} onClick={() => onProbe('/health', 'GET', undefined, '')}>
          Health · 200
        </button>
        <button type="button" className="secondary" disabled={busy} onClick={() => onProbe('/me', 'GET', undefined, '')}>
          Sin token · 401
        </button>
        <button type="button" className="secondary" disabled={busy} onClick={() => onProbe('/me', 'GET', undefined, 'token.falso.jwt')}>
          Token falso · 401
        </button>
        <button type="button" className="secondary" disabled={busy} onClick={() => onProbe('/auth/register', 'POST', { email: 'lab@example.test', password: 'corta' }, '')}>
          Contraseña corta · 400
        </button>
        <button type="button" className="secondary" disabled={busy} onClick={() => onProbe('/notes', 'POST', { content: 'Sin CSRF' }, undefined, true)}>
          Escritura sin CSRF · 403
        </button>
        <button type="button" className="secondary" disabled={busy} onClick={() => onProbe('/me', 'GET')}>
          Mi perfil · 200/401
        </button>
        <button type="button" className="secondary" disabled={busy} onClick={onConcurrentRefresh}>
          Refresh concurrente (mutex cliente)
        </button>
        <button type="button" className="secondary" disabled={busy} onClick={() => onProbe('/admin/users', 'GET')}>
          Admin usuarios · {user?.role === 'admin' ? '200' : '403/401'}
        </button>
        <button type="button" className="secondary" disabled={busy} onClick={() => onProbe('/admin/audit', 'GET')}>
          Admin auditoría · {user?.role === 'admin' ? '200' : '403/401'}
        </button>
        <button type="button" className="secondary" disabled={busy} onClick={() => onProbe('/notes/00000000-0000-4000-8000-000000000000', 'DELETE')}>
          Nota ajena · 404/401
        </button>
      </div>
    </section>
  );
}
