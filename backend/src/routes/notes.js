import express from 'express';
import { z } from 'zod';

const uuid = z.string().uuid();
const createNoteSchema = z.object({
  title: z.string().trim().max(160).default(''),
  content: z.string().trim().min(1).max(5000)
}).strict();

const updateNoteSchema = z.object({
  title: z.string().trim().max(160).optional(),
  content: z.string().trim().min(1).max(5000).optional()
}).strict().refine((data) => data.title !== undefined || data.content !== undefined, {
  message: 'Debes enviar title o content para actualizar'
});

export function createNotesRouter({ pool, security }) {
  const router = express.Router();

  router.get('/', security.requireAuth, async (req, res) => {
    const result = await pool.query(
      'select id, title, content, created_at, updated_at from app_private.notes where user_id = $1 order by created_at desc',
      [req.user.id]
    );
    return res.json(result.rows);
  });

  router.get('/:id', security.requireAuth, async (req, res) => {
    const id = uuid.parse(req.params.id);
    const result = await pool.query(
      'select id, title, content, created_at, updated_at from app_private.notes where id = $1 and user_id = $2',
      [id, req.user.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Nota no encontrada' });
    return res.json(result.rows[0]);
  });

  router.post('/', security.requireAuth, security.requireCsrf, async (req, res) => {
    const data = createNoteSchema.parse(req.body);
    const result = await pool.query(
      'insert into app_private.notes (user_id, title, content) values ($1, $2, $3) returning id, title, content, created_at, updated_at',
      [req.user.id, data.title, data.content]
    );
    await security.audit(req.user.id, 'NOTE_CREATED', req, { noteId: result.rows[0].id });
    return res.status(201).json(result.rows[0]);
  });

  router.patch('/:id', security.requireAuth, security.requireCsrf, async (req, res) => {
    const id = uuid.parse(req.params.id);
    const data = updateNoteSchema.parse(req.body);
    const result = await pool.query(
      `update app_private.notes
       set title = coalesce($1, title),
           content = coalesce($2, content)
       where id = $3 and user_id = $4
       returning id, title, content, created_at, updated_at`,
      [data.title ?? null, data.content ?? null, id, req.user.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Nota no encontrada' });
    await security.audit(req.user.id, 'NOTE_UPDATED', req, { noteId: id });
    return res.json(result.rows[0]);
  });

  router.delete('/:id', security.requireAuth, security.requireCsrf, async (req, res) => {
    const id = uuid.parse(req.params.id);
    const result = await pool.query('delete from app_private.notes where id = $1 and user_id = $2', [id, req.user.id]);
    if (!result.rowCount) return res.status(404).json({ error: 'Nota no encontrada' });
    await security.audit(req.user.id, 'NOTE_DELETED', req, { noteId: id });
    return res.sendStatus(204);
  });

  return router;
}
