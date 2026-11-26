import React from 'react';

function statusTone(status) {
  if (status >= 200 && status < 300) return 'ok';
  if (status >= 400 && status < 500) return 'warn';
  return 'err';
}

export function InspectorPanel({ history, selected, onSelect, onClear }) {
  const current = selected || history[0] || null;

  return (
    <section className="card wide" aria-label="Inspector HTTP">
      <div className="row-between">
        <div>
          <h2>Inspector de peticiones y respuestas HTTP</h2>
          <p className="muted">
            Las respuestas están sanitizadas: tokens, contraseñas y secretos MFA nunca se muestran en el inspector.
          </p>
        </div>
        {history.length > 0 && (
          <button type="button" className="secondary" onClick={onClear}>
            Limpiar historial
          </button>
        )}
      </div>

      {current ? (
        <div className="inspector-grid">
          <div className="inspector-list" role="list">
            {history.map((item) => (
              <button
                key={item.id}
                type="button"
                className={`inspector-item ${current.id === item.id ? 'active' : ''}`}
                onClick={() => onSelect(item)}
              >
                <span className={`badge ${statusTone(item.status)}`}>{item.status || 'ERR'}</span>
                <span className="mono">{item.method} {item.path}</span>
                <span className="muted">{item.durationMs} ms</span>
              </button>
            ))}
          </div>
          <div className="inspector-detail">
            <div className="inspector-meta">
              <span className={`badge ${statusTone(current.status)}`}>HTTP {current.status}</span>
              <span className="mono">{current.method} {current.path}</span>
              <span className="muted">{current.durationMs} ms</span>
            </div>
            {current.requestBody && (
              <>
                <p className="label-sm">Cuerpo enviado (sanitizado)</p>
                <pre>{JSON.stringify(current.requestBody, null, 2)}</pre>
              </>
            )}
            <p className="label-sm">Respuesta del servidor</p>
            <pre>{JSON.stringify(current.data ?? { status: current.status }, null, 2)}</pre>
          </div>
        </div>
      ) : (
        <pre>Ejecuta una acción o prueba del laboratorio para inspeccionar el tráfico HTTP.</pre>
      )}
    </section>
  );
}
