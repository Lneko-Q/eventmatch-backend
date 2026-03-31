// Backend API for EventMatch - Node.js Express Server
// Run: npm install && node BACKEND_EXAMPLE.js

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
// Render sets PORT and provides a writable /tmp or /var/data; use provided PORT
const PORT = process.env.PORT || 5000;

// Optional: respect Render's recommended disk path for persistent files
if (process.env.RENDER_DATA_DIR) {
  console.log('[backend] Running on Render, using RENDER_DATA_DIR for DB if available');
}

// Middleware
app.use(cors());
app.use(express.json());

// Simple request logger
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next();
});

// Initialize SQLite Database
// Allow overriding DB path via environment (use Render persistent disk path if set)
const dbPath = process.env.EVENTMATCH_DB_PATH || path.join(__dirname, 'eventmatch.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error('Database error:', err);
  else console.log('Connected to SQLite database:', dbPath);
});

// Create tables
db.serialize(() => {

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      isAdmin INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS groups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      ownerEmail TEXT NOT NULL,
      memberCount INTEGER DEFAULT 1,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS groupMembers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      groupId INTEGER NOT NULL,
      userEmail TEXT NOT NULL,
      joinedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (groupId) REFERENCES groups(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS groupMessages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      groupId INTEGER NOT NULL,
      fromEmail TEXT NOT NULL,
      text TEXT NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (groupId) REFERENCES groups(id)
    )
  `);

  console.log('Database tables ready');

  // Create admin account if not exists
  const adminEmail = 'admin';
  const adminPass = 'admin';
  db.get('SELECT * FROM users WHERE email = ?', [adminEmail], async (err, row) => {
    if (!row) {
      const bcrypt = require('bcryptjs');
      const hashed = await bcrypt.hash(adminPass, 10);
      db.run('INSERT INTO users (email, password, isAdmin) VALUES (?, ?, 1)', [adminEmail, hashed], (err2) => {
        if (!err2) console.log('[backend] Admin account created: admin/admin');
      });
    }
  });
});

// ============= AUTH =============
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    // Normalize email: lowercase and trim
    const normalizedEmail = email.toLowerCase().trim();
    const hashed = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (email, password) VALUES (?, ?)', [normalizedEmail, hashed], function(err) {
      if (err) {
        if (err.message && err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Email already exists' });
        return res.status(500).json({ error: 'Registration failed' });
      }
      res.status(201).json({ message: 'User registered successfully', email: normalizedEmail, id: this.lastID });
    });
  } catch (ex) { res.status(500).json({ error: ex.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    // Normalize email: lowercase and trim
    const normalizedEmail = email.toLowerCase().trim();
    db.get('SELECT id, email, password FROM users WHERE email = ?', [normalizedEmail], async (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });
      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
      res.json({ id: user.id, email: user.email });
    });
  } catch (ex) { res.status(500).json({ error: ex.message }); }
});

app.get('/api/auth/exists/:email', (req, res) => {
  const { email } = req.params;
  // Normalize email: lowercase and trim
  const normalizedEmail = email.toLowerCase().trim();
  db.get('SELECT email FROM users WHERE email = ?', [normalizedEmail], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (row) return res.json({ exists: true });
    return res.status(404).json({ exists: false });
  });
});

// Optional admin endpoint to list users

// List all users (admin only, protected by ADMIN_TOKEN)
app.get('/api/users', (req, res) => {
  const token = (req.headers['x-admin-token'] || '').toString();
  if (!process.env.ADMIN_TOKEN || token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  db.all('SELECT id, email, isAdmin, created_at FROM users ORDER BY created_at DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows || []);
  });
});

// Delete user by email (admin only, protected by ADMIN_TOKEN)
app.delete('/api/users/:email', (req, res) => {
  const token = (req.headers['x-admin-token'] || '').toString();
  if (!process.env.ADMIN_TOKEN || token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const { email } = req.params;
  db.run('DELETE FROM users WHERE email = ?', [email], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete user' });
    res.json({ message: 'User deleted', email });
  });
});

// ============= GROUPS =============
app.post('/api/groups/create', (req, res) => {
  try {
    const { name, description, ownerEmail, memberCount } = req.body;
    if (!name || !ownerEmail) return res.status(400).json({ error: 'Name and ownerEmail required' });
    // Normalize ownerEmail: lowercase and trim
    const normalizedOwnerEmail = ownerEmail.toLowerCase().trim();
    const createdAt = new Date().toISOString();
    db.run('INSERT INTO groups (name, description, ownerEmail, memberCount, createdAt) VALUES (?, ?, ?, ?, ?)',
      [name, description || '', normalizedOwnerEmail, memberCount || 1, createdAt], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to create group' });
        const id = this.lastID;
        // add owner as member
        db.run('INSERT INTO groupMembers (groupId, userEmail) VALUES (?, ?)', [id, normalizedOwnerEmail]);
        res.status(201).json({ id, name, description: description || '', ownerEmail: normalizedOwnerEmail, memberCount: memberCount || 1, createdAt });
      });
  } catch (ex) { res.status(500).json({ error: ex.message }); }
});

app.get('/api/groups/user/:email', (req, res) => {
  const { email } = req.params;
  db.all(`SELECT DISTINCT g.* FROM groups g
          LEFT JOIN groupMembers gm ON g.id = gm.groupId
          WHERE g.ownerEmail = ? OR gm.userEmail = ?
          ORDER BY g.createdAt DESC`, [email, email], (err, groups) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(groups || []);
  });
});

// Return all groups (public browse)
app.get('/api/groups', (req, res) => {
  db.all('SELECT * FROM groups ORDER BY createdAt DESC', [], (err, groups) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(groups || []);
  });
});

app.get('/api/groups/:id', (req, res) => {
  const { id } = req.params;
  db.get('SELECT * FROM groups WHERE id = ?', [id], (err, g) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!g) return res.status(404).json({ error: 'Group not found' });
    res.json(g);
  });
});

app.put('/api/groups/:id', (req, res) => {
  const { id } = req.params; const { name, description, memberCount } = req.body;
  // Require x-user-email header to authorize update (only owner may update)
  const userEmail = (req.headers['x-user-email'] || '').toString().toLowerCase().trim();
  if (!userEmail) return res.status(401).json({ error: 'Unauthorized - user email required' });

  db.get('SELECT ownerEmail FROM groups WHERE id = ?', [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'Group not found' });
    // Compare emails case-insensitive and trimmed
    const owner = (row.ownerEmail || '').toLowerCase().trim();
    if (owner !== userEmail) return res.status(403).json({ error: 'Forbidden - only owner can update group' });

    db.run('UPDATE groups SET name = ?, description = ?, memberCount = ? WHERE id = ?', [name, description, memberCount, id], function(err2) {
      if (err2) return res.status(500).json({ error: 'Failed to update group' });
      res.json({ message: 'Group updated', id });
    });
  });
});

app.delete('/api/groups/:id', (req, res) => {
  const { id } = req.params;
  const userEmail = (req.headers['x-user-email'] || '').toString().toLowerCase().trim();
  if (!userEmail) return res.status(401).json({ error: 'Unauthorized - user email required' });

  db.get('SELECT ownerEmail FROM groups WHERE id = ?', [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'Group not found' });
    // Compare emails case-insensitive and trimmed
    const owner = (row.ownerEmail || '').toLowerCase().trim();
    if (owner !== userEmail) return res.status(403).json({ error: 'Forbidden - only owner can delete group' });

    db.serialize(() => {
      db.run('DELETE FROM groupMessages WHERE groupId = ?', [id]);
      db.run('DELETE FROM groupMembers WHERE groupId = ?', [id]);
      db.run('DELETE FROM groups WHERE id = ?', [id], function(err2) {
        if (err2) return res.status(500).json({ error: 'Failed to delete group' });
        res.json({ message: 'Group deleted' });
      });
    });
  });
});

app.post('/api/groups/add-member', (req, res) => {
  const { groupId, userEmail } = req.body;
  if (!groupId || !userEmail) return res.status(400).json({ error: 'GroupId and userEmail required' });
  db.get('SELECT * FROM groupMembers WHERE groupId = ? AND userEmail = ?', [groupId, userEmail], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (row) return res.status(400).json({ error: 'User already member' });
    db.run('INSERT INTO groupMembers (groupId, userEmail) VALUES (?, ?)', [groupId, userEmail], function(err2) {
      if (err2) return res.status(500).json({ error: 'Failed to add member' });
      db.run('UPDATE groups SET memberCount = memberCount + 1 WHERE id = ?', [groupId]);
      res.json({ message: 'Member added' });
    });
  });
});

app.post('/api/groups/messages', (req, res) => {
  const { groupId, fromEmail, text } = req.body;
  if (!groupId || !fromEmail || !text) return res.status(400).json({ error: 'GroupId, fromEmail, and text required' });
  const ts = new Date().toISOString();
  db.run('INSERT INTO groupMessages (groupId, fromEmail, text, timestamp) VALUES (?, ?, ?, ?)', [groupId, fromEmail, text, ts], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to add message' });
    res.status(201).json({ id: this.lastID, groupId, fromEmail, text, timestamp: ts });
  });
});

app.get('/api/groups/:id/messages', (req, res) => {
  const { id } = req.params;
  db.all('SELECT * FROM groupMessages WHERE groupId = ? ORDER BY timestamp ASC', [id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows || []);
  });
});

app.get('/api/groups/:id/members', (req, res) => {
  const { id } = req.params;
  db.all('SELECT userEmail FROM groupMembers WHERE groupId = ?', [id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json((rows || []).map(r => r.userEmail));
  });
});

// Health
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Server is running' });
});

app.listen(PORT, () => {
  console.log(`EventMatch backend listening on port ${PORT}`);
});

process.on('SIGINT', () => { db.close(); process.exit(0); });
