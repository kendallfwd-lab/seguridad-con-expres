import React, { useEffect, useState } from 'react';

export function NotesView({ busy, notes, onLoadNotes, onCreateNote, onUpdateNote, onDeleteNote, onProbeOwnership }) {
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [editingId, setEditingId] = useState(null);
  const [editTitle, setEditTitle] = useState('');
  const [editContent, setEditContent] = useState('');
  const [probeId, setProbeId] = useState('');
  const [feedback, setFeedback] = useState(null);

  useEffect(() => {
    onLoadNotes();
  }, []);

  return (
    <section className="card">
      <div className="row-between">
        <div>
          <h2>Notas privadas</h2>
          <p className="muted">CRUD completo con verificación estricta de propiedad (`user_id = req.user.id`) en PostgreSQL.</p>
        </div>
        <button type="button" className="secondary" disabled={busy} onClick={onLoadNotes}>
          Recargar
        </button>
      </div>

      {feedback && <p className={`alert ${feedback.ok ? 'ok' : 'err'}`}>{feedback.message}</p>}

      <form onSubmit={async (e) => {
        e.preventDefault();
        setFeedback(null);
        const r = await onCreateNote(title, content);
        if (r.ok) {
          setTitle('');
          setContent('');
          setFeedback({ ok: true, message: 'Nota creada.' });
        } else {
          setFeedback({ ok: false, message: r.data?.error || 'Error al crear la nota' });
        }
      }}>
        <label>
          Título
          <input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={160} placeholder="Opcional" />
        </label>
        <label>
          Contenido
          <textarea value={content} onChange={(e) => setContent(e.target.value)} maxLength={5000} rows={3} required />
        </label>
        <button disabled={busy}>{busy ? 'Guardando...' : 'Crear nota'}</button>
      </form>

      <div className="notes-list">
        {notes.length === 0 ? (
          <p className="muted">Aún no tienes notas registradas.</p>
        ) : notes.map((note) => (
          <div className="note-card" key={note.id}>
            {editingId === note.id ? (
              <form className="note-edit" onSubmit={async (e) => {
                e.preventDefault();
                const r = await onUpdateNote(note.id, editTitle, editContent);
                if (r.ok) {
                  setEditingId(null);
                  setFeedback({ ok: true, message: 'Nota actualizada.' });
                } else {
                  setFeedback({ ok: false, message: r.data?.error || 'Error al actualizar' });
                }
              }}>
                <input value={editTitle} onChange={(e) => setEditTitle(e.target.value)} maxLength={160} />
                <textarea value={editContent} onChange={(e) => setEditContent(e.target.value)} rows={2} required />
                <div className="actions">
                  <button disabled={busy}>Guardar</button>
                  <button type="button" className="secondary" onClick={() => setEditingId(null)}>Cancelar</button>
                </div>
              </form>
            ) : (
              <>
                <div className="note-body">
                  <strong>{note.title || '(Sin título)'}</strong>
                  <p>{note.content}</p>
                  <span className="mono muted">{note.id}</span>
                </div>
                <div className="actions">
                  <button
                    type="button"
                    className="secondary"
                    disabled={busy}
                    onClick={() => {
                      setEditingId(note.id);
                      setEditTitle(note.title || '');
                      setEditContent(note.content);
                    }}
                  >
                    Editar
                  </button>
                  <button
                    type="button"
                    className="danger"
                    disabled={busy}
                    onClick={() => onDeleteNote(note.id)}
                  >
                    Eliminar
                  </button>
                </div>
              </>
            )}
          </div>
        ))}
      </div>

      <hr />
      <h3>Prueba de propiedad (IDOR / BOLA)</h3>
      <label>
        UUID de nota de otra cuenta
        <input
          value={probeId}
          onChange={(e) => setProbeId(e.target.value)}
          placeholder="00000000-0000-4000-8000-000000000000"
        />
      </label>
      <div className="actions">
        <button
          type="button"
          className="secondary"
          disabled={busy || !probeId.trim()}
          onClick={() => onProbeOwnership('GET', probeId.trim())}
        >
          Intentar leer (404)
        </button>
        <button
          type="button"
          className="secondary"
          disabled={busy || !probeId.trim()}
          onClick={() => onProbeOwnership('DELETE', probeId.trim())}
        >
          Intentar eliminar (404)
        </button>
      </div>
    </section>
  );
}
