const router    = require('express').Router();
const bcrypt    = require('bcrypt');
const jwt       = require('jsonwebtoken');
const Joi       = require('joi');
const pool      = require('../../config/database');

const registerSchema = Joi.object({
  email:    Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const loginSchema = Joi.object({
  email:    Joi.string().email().required(),
  password: Joi.string().required(),
});

function signAccess(payload) {
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.JWT_ACCESS_EXPIRY || '15m',
  });
}

function signRefresh(payload) {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRY || '7d',
  });
}

// POST /auth/register
router.post('/register', async (req, res, next) => {
  try {
    const { error, value } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    const exists = await pool.query('SELECT id FROM users WHERE email = $1', [value.email]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(value.password, 12);
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, created_at',
      [value.email, hash]
    );

    res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

// POST /auth/login
router.post('/login', async (req, res, next) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [value.email]);
    const user   = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(value.password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const payload      = { userId: user.id, email: user.email };
    const accessToken  = signAccess(payload);
    const refreshToken = signRefresh({ userId: user.id });

    const hash       = await bcrypt.hash(refreshToken, 8);
    const expiresAt  = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await pool.query(
      'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
      [user.id, hash, expiresAt]
    );

    res.json({ accessToken, refreshToken, user: { id: user.id, email: user.email } });
  } catch (err) {
    next(err);
  }
});

// POST /auth/refresh
router.post('/refresh', async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });

    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }

    // Find matching token in DB
    const rows = await pool.query(
      'SELECT * FROM refresh_tokens WHERE user_id = $1 AND expires_at > NOW()',
      [decoded.userId]
    );

    let matched = null;
    for (const row of rows.rows) {
      if (await bcrypt.compare(refreshToken, row.token_hash)) {
        matched = row;
        break;
      }
    }
    if (!matched) return res.status(403).json({ error: 'Refresh token not recognised' });

    // Rotate: delete old, issue new
    await pool.query('DELETE FROM refresh_tokens WHERE id = $1', [matched.id]);

    const userResult = await pool.query('SELECT id, email FROM users WHERE id = $1', [decoded.userId]);
    const user       = userResult.rows[0];

    const newAccessToken  = signAccess({ userId: user.id, email: user.email });
    const newRefreshToken = signRefresh({ userId: user.id });

    const newHash    = await bcrypt.hash(newRefreshToken, 8);
    const expiresAt  = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await pool.query(
      'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
      [user.id, newHash, expiresAt]
    );

    res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch (err) {
    next(err);
  }
});

// POST /auth/logout
router.post('/logout', async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });

    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }

    const rows = await pool.query(
      'SELECT * FROM refresh_tokens WHERE user_id = $1',
      [decoded.userId]
    );

    for (const row of rows.rows) {
      if (await bcrypt.compare(refreshToken, row.token_hash)) {
        await pool.query('DELETE FROM refresh_tokens WHERE id = $1', [row.id]);
        break;
      }
    }

    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
