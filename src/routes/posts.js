const router = require('express').Router();
const Joi    = require('joi');
const pool   = require('../../config/database');
const auth   = require('../middleware/auth');

const postSchema = Joi.object({
  title:   Joi.string().min(1).max(255).required(),
  content: Joi.string().min(1).required(),
});

// GET /posts  — public, paginated
router.get('/', async (req, res, next) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page)  || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 10);
    const offset = (page - 1) * limit;

    const [data, total] = await Promise.all([
      pool.query(
        `SELECT p.id, p.title, p.content, p.created_at, p.updated_at,
                u.id AS author_id, u.email AS author_email
         FROM posts p
         JOIN users u ON u.id = p.user_id
         ORDER BY p.created_at DESC
         LIMIT $1 OFFSET $2`,
        [limit, offset]
      ),
      pool.query('SELECT COUNT(*) FROM posts'),
    ]);

    res.json({
      data:       data.rows,
      pagination: {
        page,
        limit,
        total:      parseInt(total.rows[0].count),
        totalPages: Math.ceil(total.rows[0].count / limit),
      },
    });
  } catch (err) {
    next(err);
  }
});

// GET /posts/:id — public
router.get('/:id', async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT p.id, p.title, p.content, p.created_at, p.updated_at,
              u.id AS author_id, u.email AS author_email
       FROM posts p
       JOIN users u ON u.id = p.user_id
       WHERE p.id = $1`,
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Post not found' });
    res.json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

// POST /posts — protected
router.post('/', auth, async (req, res, next) => {
  try {
    const { error, value } = postSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    const result = await pool.query(
      'INSERT INTO posts (user_id, title, content) VALUES ($1, $2, $3) RETURNING *',
      [req.user.userId, value.title, value.content]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

// PUT /posts/:id — protected, owner only
router.put('/:id', auth, async (req, res, next) => {
  try {
    const { error, value } = postSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    const post = await pool.query('SELECT user_id FROM posts WHERE id = $1', [req.params.id]);
    if (!post.rows.length) return res.status(404).json({ error: 'Post not found' });
    if (post.rows[0].user_id !== req.user.userId) return res.status(403).json({ error: 'Forbidden' });

    const result = await pool.query(
      `UPDATE posts SET title = $1, content = $2, updated_at = NOW()
       WHERE id = $3 RETURNING *`,
      [value.title, value.content, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

// DELETE /posts/:id — protected, owner only
router.delete('/:id', auth, async (req, res, next) => {
  try {
    const post = await pool.query('SELECT user_id FROM posts WHERE id = $1', [req.params.id]);
    if (!post.rows.length) return res.status(404).json({ error: 'Post not found' });
    if (post.rows[0].user_id !== req.user.userId) return res.status(403).json({ error: 'Forbidden' });

    await pool.query('DELETE FROM posts WHERE id = $1', [req.params.id]);
    res.json({ message: 'Post deleted' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
