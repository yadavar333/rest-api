require('dotenv').config();
const express    = require('express');
const morgan     = require('morgan');
const rateLimit  = require('express-rate-limit');

const authRoutes  = require('./routes/auth');
const postsRoutes = require('./routes/posts');
const authMw      = require('./middleware/auth');
const errorHandler = require('./middleware/errorHandler');

const app = express();

app.use(express.json());
app.use(morgan('dev'));

// Rate limit auth routes — 20 requests per 15 minutes per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      20,
  message:  { error: 'Too many requests, please try again later' },
});

app.use('/auth', authLimiter, authRoutes);
app.use('/posts', postsRoutes);

// GET /me — protected
app.get('/me', authMw, async (req, res, next) => {
  try {
    const pool   = require('../config/database');
    const result = await pool.query(
      'SELECT id, email, created_at FROM users WHERE id = $1',
      [req.user.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use(errorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

module.exports = app;
