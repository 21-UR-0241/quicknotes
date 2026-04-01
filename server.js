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
const PORT   = process.env.PORT || 3000;

// ── SSE broadcast store ────────────────────────────────────────────────────────
// sseClients: adminId -> Set<res>
// sseUsers:   userId  -> Set<res>
const sseClients = new Map();
const sseUsers   = new Map();

function sseAdd(groupKey, userId, res) {
  if (!sseClients.has(groupKey)) sseClients.set(groupKey, new Set());
  sseClients.get(groupKey).add(res);
  if (!sseUsers.has(userId)) sseUsers.set(userId, new Set());
  sseUsers.get(userId).add(res);
}
function sseRemove(groupKey, userId, res) {
  sseClients.get(groupKey)?.delete(res);
  sseUsers.get(userId)?.delete(res);
}
function sseBroadcast(adminId) {
  const clients = sseClients.get(adminId);
  if (!clients || clients.size === 0) return;
  for (const res of clients) {
    try { res.write('event: notes_updated\ndata: {}\n\n'); } catch {}
  }
}
function sseUsersBroadcast(adminId) {
  const clients = sseClients.get(adminId);
  if (!clients || clients.size === 0) return;
  for (const res of clients) {
    try { res.write('event: users_updated\ndata: {}\n\n'); } catch {}
  }
}
function sseUserUpdate(userId, payload) {
  const clients = sseUsers.get(userId);
  if (!clients || clients.size === 0) return;
  const data = JSON.stringify(payload);
  for (const res of clients) {
    try { res.write(`event: user_updated\ndata: ${data}\n\n`); } catch {}
  }
}

// ── Init DB ────────────────────────────────────────────────────────────────────
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id             SERIAL PRIMARY KEY,
      username       VARCHAR(50) UNIQUE NOT NULL,
      password_hash  TEXT NOT NULL,
      is_admin       BOOLEAN DEFAULT FALSE,
      group_admin_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at     TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS notes (
      id         VARCHAR(50) PRIMARY KEY,
      user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title      TEXT DEFAULT '',
      content    TEXT DEFAULT '',
      color      VARCHAR(10) DEFAULT '',
      position   INTEGER DEFAULT 0,
      updated_at BIGINT DEFAULT 0,
      shared     BOOLEAN DEFAULT FALSE,
      share_mode VARCHAR(20) DEFAULT ''
    );
  `);

  // Safe migrations — run on every startup, ignored if column already exists
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE`).catch(() => {});
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS group_admin_id INTEGER REFERENCES users(id) ON DELETE SET NULL`).catch(() => {});
  await pool.query(`ALTER TABLE notes ADD COLUMN IF NOT EXISTS shared BOOLEAN DEFAULT FALSE`).catch(() => {});
  await pool.query(`ALTER TABLE notes ADD COLUMN IF NOT EXISTS share_mode VARCHAR(20) DEFAULT ''`).catch(() => {});

  // Clean up subadmin column if it exists from a previous version
  await pool.query(`ALTER TABLE users DROP COLUMN IF EXISTS is_subadmin`).catch(() => {});

  const { rows } = await pool.query('SELECT COUNT(*) FROM users');
  if (parseInt(rows[0].count) === 0) {
    const adminUser = process.env.ADMIN_USERNAME || 'admin';
    const adminPass = process.env.ADMIN_PASSWORD || 'admin123';
    const hash = await bcrypt.hash(adminPass, 10);
    await pool.query(
      'INSERT INTO users (username, password_hash, is_admin) VALUES ($1, $2, TRUE)',
      [adminUser, hash]
    );
    console.log(`Default admin created — username: "${adminUser}" password: "${adminPass}"`);
  }

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

// Always pull fresh user from DB so role changes are immediately reflected
async function freshUser(req, res, next) {
  try {
    const r = await pool.query(
      'SELECT id, username, is_admin, group_admin_id FROM users WHERE id = $1',
      [req.user.id]
    );
    if (!r.rows.length) return res.status(401).json({ error: 'User not found' });
    req.user = { ...req.user, ...r.rows[0] };
    next();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ── Login ──────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const r = await pool.query('SELECT * FROM users WHERE username = $1', [username.toLowerCase().trim()]);
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, r.rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const u = r.rows[0];
    const token = jwt.sign(
      { id: u.id, username: u.username, is_admin: u.is_admin, group_admin_id: u.group_admin_id },
      SECRET,
      { expiresIn: '30d' }
    );
    res.json({
      token,
      username:       u.username,
      is_admin:       u.is_admin,
      group_admin_id: u.group_admin_id
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── SSE stream ────────────────────────────────────────────────────────────────
app.get('/api/stream', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(401).end();

  let user;
  try { user = jwt.verify(token, SECRET); }
  catch { return res.status(401).end(); }

  try {
    const r = await pool.query(
      'SELECT id, username, is_admin, group_admin_id FROM users WHERE id = $1',
      [user.id]
    );
    if (!r.rows.length) return res.status(401).end();
    user = { ...user, ...r.rows[0] };
  } catch { return res.status(500).end(); }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();
  res.write('event: connected\ndata: {}\n\n');

  // Admins subscribe under their own id; members subscribe under their admin's id
  const groupKey = user.is_admin ? user.id : user.group_admin_id;
  if (groupKey) sseAdd(groupKey, user.id, res);

  const ping = setInterval(() => {
    try { res.write(':ping\n\n'); } catch {}
  }, 25000);

  req.on('close', () => {
    clearInterval(ping);
    if (groupKey) sseRemove(groupKey, user.id, res);
  });
});

// ── Notes: Get ─────────────────────────────────────────────────────────────────
app.get('/api/notes', auth, freshUser, async (req, res) => {
  try {
    let r;
    if (req.user.is_admin) {
      // Admin: own notes + all notes from everyone in the group
      r = await pool.query(`
        SELECT n.*,
               (n.user_id = $1) AS is_mine,
               u.username AS owner_username
        FROM notes n
        JOIN users u ON u.id = n.user_id
        WHERE n.user_id = $1
           OR u.group_admin_id = $1
        ORDER BY
          CASE WHEN n.user_id = $1 THEN 0 ELSE 1 END ASC,
          n.position ASC,
          n.updated_at DESC
      `, [req.user.id]);
    } else {
      // Members: own notes + notes shared by admin (shared = true)
      r = await pool.query(`
        SELECT n.*,
               (n.user_id = $1) AS is_mine,
               u.username AS owner_username
        FROM notes n
        JOIN users u ON u.id = n.user_id
        WHERE n.user_id = $1
           OR (n.shared = TRUE AND n.user_id = $2)
        ORDER BY
          CASE WHEN n.user_id = $1 THEN 0 ELSE 1 END ASC,
          n.position ASC,
          n.updated_at DESC
      `, [req.user.id, req.user.group_admin_id]);
    }
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Notes: Save ───────────────────────────────────────────────────────────────
app.put('/api/notes/:id', auth, freshUser, async (req, res) => {
  const { title, content, color, position, updated_at, shared, share_mode } = req.body;

  try {
    // Check ownership
    const check = await pool.query('SELECT user_id, shared, share_mode FROM notes WHERE id = $1', [req.params.id]);
    const existingNote = check.rows[0];

    if (existingNote) {
      const isOwner = existingNote.user_id === req.user.id;
      // Member can only edit if share_mode is 'editable'
      const canEditAsNonOwner = !req.user.is_admin && !isOwner &&
        existingNote.share_mode === 'editable';
      if (!isOwner && !canEditAsNonOwner && !req.user.is_admin) {
        return res.status(403).json({ error: 'Not allowed to edit this note' });
      }
    }

    // Only admin (owner) can change shared/share_mode — members preserve existing values
    let sharedVal, shareModeVal;
    if (req.user.is_admin) {
      sharedVal    = shared === true;
      shareModeVal = share_mode || '';
    } else if (existingNote) {
      // Member editing editable note: preserve shared/share_mode as-is
      sharedVal    = existingNote.shared;
      shareModeVal = existingNote.share_mode;
    } else {
      sharedVal    = false;
      shareModeVal = '';
    }

    // Ownership: members never take ownership of admin notes
    const noteUserId = (existingNote && existingNote.user_id !== req.user.id)
      ? existingNote.user_id
      : req.user.id;

    await pool.query(`
      INSERT INTO notes (id, user_id, title, content, color, position, updated_at, shared, share_mode)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      ON CONFLICT (id) DO UPDATE SET
        title      = EXCLUDED.title,
        content    = EXCLUDED.content,
        color      = EXCLUDED.color,
        position   = EXCLUDED.position,
        updated_at = EXCLUDED.updated_at,
        shared     = EXCLUDED.shared,
        share_mode = EXCLUDED.share_mode
    `, [req.params.id, noteUserId, title || '', content || '', color || '',
        position || 0, updated_at || Date.now(), sharedVal, shareModeVal]);

    const broadcastId = req.user.is_admin ? req.user.id : req.user.group_admin_id;
    if (broadcastId) sseBroadcast(broadcastId);

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Notes: Toggle shared + share_mode (admin only) ────────────────────────────
app.patch('/api/notes/:id/shared', auth, freshUser, adminOnly, async (req, res) => {
  const { shared, share_mode } = req.body;
  try {
    const r = await pool.query(
      `UPDATE notes SET shared = $1, share_mode = $2
       WHERE id = $3 AND user_id = $4 RETURNING id`,
      [!!shared, share_mode || '', req.params.id, req.user.id]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Note not found' });
    sseBroadcast(req.user.id);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Notes: Delete ──────────────────────────────────────────────────────────────
app.delete('/api/notes/:id', auth, freshUser, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM notes WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    const broadcastId = req.user.is_admin ? req.user.id : req.user.group_admin_id;
    if (broadcastId) sseBroadcast(broadcastId);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Notes: Reorder ─────────────────────────────────────────────────────────────
app.post('/api/notes/reorder', auth, freshUser, async (req, res) => {
  const { order } = req.body;
  try {
    for (let i = 0; i < order.length; i++) {
      await pool.query(
        'UPDATE notes SET position = $1 WHERE id = $2 AND user_id = $3',
        [i, order[i], req.user.id]
      );
    }
    const broadcastId = req.user.is_admin ? req.user.id : req.user.group_admin_id;
    if (broadcastId) sseBroadcast(broadcastId);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── ADMIN: List users ──────────────────────────────────────────────────────────
app.get('/api/admin/users', auth, freshUser, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT id, username, is_admin, group_admin_id, created_at,
        (SELECT COUNT(*) FROM notes WHERE user_id = users.id)::int AS note_count
      FROM users
      WHERE id = $1 OR group_admin_id = $1
      ORDER BY is_admin DESC, created_at ASC
    `, [req.user.id]);
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── ADMIN: Create user ─────────────────────────────────────────────────────────
app.post('/api/admin/users', auth, freshUser, adminOnly, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  if (username.length < 3)    return res.status(400).json({ error: 'Username too short (min 3)' });
  if (password.length < 6)    return res.status(400).json({ error: 'Password too short (min 6)' });

  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `INSERT INTO users (username, password_hash, is_admin, group_admin_id)
       VALUES ($1, $2, FALSE, $3)
       RETURNING id, username, is_admin, group_admin_id, created_at`,
      [username.toLowerCase().trim(), hash, req.user.id]
    );
    sseUsersBroadcast(req.user.id);
    res.json({ ...r.rows[0], note_count: 0 });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Username already taken' });
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── ADMIN: Reset any user's password (admin only) ─────────────────────────────
app.patch('/api/admin/users/:id/password', auth, freshUser, adminOnly, async (req, res) => {
  const { password } = req.body || {};
  if (!password)           return res.status(400).json({ error: 'Missing password' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short (min 6)' });

  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `UPDATE users SET password_hash = $1
       WHERE id = $2 AND (group_admin_id = $3 OR id = $3)
       RETURNING id`,
      [hash, req.params.id, req.user.id]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── ADMIN: Delete user ─────────────────────────────────────────────────────────
app.delete('/api/admin/users/:id', auth, freshUser, adminOnly, async (req, res) => {
  const targetId = parseInt(req.params.id);
  if (targetId === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account' });
  try {
    const r = await pool.query(
      'DELETE FROM users WHERE id = $1 AND group_admin_id = $2 RETURNING id',
      [targetId, req.user.id]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'User not found in your group' });
    sseUsersBroadcast(req.user.id);
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