require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json({ limit: '20mb' }));
app.use(express.static('public'));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const PORT = process.env.PORT || 3000;

// ── Init DB tables ─────────────────────────────────────────────────────────────
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS notes (
      id VARCHAR(50) PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title TEXT DEFAULT '',
      content TEXT DEFAULT '',
      color VARCHAR(10) DEFAULT '',
      position INTEGER DEFAULT 0,
      updated_at BIGINT DEFAULT 0
    );
  `);
  console.log('DB ready');
}

// ── Auth middleware ────────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── Register ───────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  if (username.length < 3) return res.status(400).json({ error: 'Username too short' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
      [username.toLowerCase().trim(), hash]
    );
    const token = jwt.sign({ id: r.rows[0].id, username: r.rows[0].username }, SECRET, { expiresIn: '30d' });
    res.json({ token, username: r.rows[0].username });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Username already taken' });
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Login ──────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const r = await pool.query('SELECT * FROM users WHERE username = $1', [username.toLowerCase().trim()]);
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, r.rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: r.rows[0].id, username: r.rows[0].username }, SECRET, { expiresIn: '30d' });
    res.json({ token, username: r.rows[0].username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Get notes ──────────────────────────────────────────────────────────────────
app.get('/api/notes', auth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT * FROM notes WHERE user_id = $1 ORDER BY position ASC, updated_at DESC',
      [req.user.id]
    );
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Save note (create or update) ───────────────────────────────────────────────
app.put('/api/notes/:id', auth, async (req, res) => {
  const { title, content, color, position, updated_at } = req.body;
  try {
    await pool.query(`
      INSERT INTO notes (id, user_id, title, content, color, position, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT (id) DO UPDATE SET
        title = EXCLUDED.title,
        content = EXCLUDED.content,
        color = EXCLUDED.color,
        position = EXCLUDED.position,
        updated_at = EXCLUDED.updated_at
    `, [req.params.id, req.user.id, title || '', content || '', color || '', position || 0, updated_at || Date.now()]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Delete note ────────────────────────────────────────────────────────────────
app.delete('/api/notes/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM notes WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Reorder notes ──────────────────────────────────────────────────────────────
app.post('/api/notes/reorder', auth, async (req, res) => {
  const { order } = req.body;
  try {
    for (let i = 0; i < order.length; i++) {
      await pool.query(
        'UPDATE notes SET position = $1 WHERE id = $2 AND user_id = $3',
        [i, order[i], req.user.id]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Start ──────────────────────────────────────────────────────────────────────
initDb().then(() => {
  app.listen(PORT, () => console.log(`QuickNotes running on http://localhost:${PORT}`));
}).catch(e => {
  console.error('DB init failed:', e);
  process.exit(1);
});