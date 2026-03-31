// Backend API for EventMatch - Node.js Express Server
// Deploy to Render.com or Heroku for production

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Simple request logger for debugging on Render
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    next();
});

// Initialize SQLite Database
const dbPath = path.join(__dirname, 'eventmatch.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('Database error:', err);
    else console.log('Connected to SQLite database');
});

// Initialize tables
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
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
    console.log('Database tables created/verified');
});

// ============= Auth Routes =============

/**
 * POST /api/auth/register
 * Register a new user
 */
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user
        db.run(
            'INSERT INTO users (email, password) VALUES (?, ?)',
            [email, hashedPassword],
            (err) => {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(409).json({ error: 'Email already exists' });
                    }
                    return res.status(500).json({ error: 'Registration failed' });
                }
                res.status(201).json({ 
                    message: 'User registered successfully',
                    email: email
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/auth/login
 * Authenticate user and return user object
 */
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        // Find user
        db.get(
            'SELECT id, email, password FROM users WHERE email = ?',
            [email],
            async (err, user) => {
                if (err) {
                    return res.status(500).json({ error: 'Database error' });
                }

                if (!user) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                // Verify password
                const validPassword = await bcrypt.compare(password, user.password);
                if (!validPassword) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                // Return user object (matching the C# User model)
                res.json({
                    id: user.id,
                    email: user.email,
                    password: password // Return plain password (already validated)
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/auth/exists/:email
 * Check if user exists
 */
app.get('/api/auth/exists/:email', (req, res) => {
    try {
        const { email } = req.params;

        db.get(
            'SELECT email FROM users WHERE email = ?',
            [email],
            (err, user) => {
                if (err) {
                    return res.status(500).json({ error: 'Database error' });
                }

                if (user) {
                    res.status(200).json({ exists: true });
                } else {
                    res.status(404).json({ exists: false });
                }
            }
        );
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/health
 * Health check endpoint
 */
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Server is running' });
});

// ============= GROUP ROUTES =============

/**
 * POST /api/groups/create
 * Create a new group
 */
app.post('/api/groups/create', (req, res) => {
    try {
        const { name, description, ownerEmail, memberCount } = req.body;

        if (!name || !ownerEmail) {
            return res.status(400).json({ error: 'Name and ownerEmail required' });
        }

        const groupData = {
            name,
            description: description || '',
            ownerEmail,
            memberCount: memberCount || 1,
            createdAt: new Date().toISOString()
        };

        db.run(
            'INSERT INTO groups (name, description, ownerEmail, memberCount, createdAt) VALUES (?, ?, ?, ?, ?)',
            [groupData.name, groupData.description, groupData.ownerEmail, groupData.memberCount, groupData.createdAt],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Failed to create group' });
                }
                const id = this.lastID;
                // add owner as member
                db.run('INSERT INTO groupMembers (groupId, userEmail) VALUES (?, ?)', [id, ownerEmail]);
                res.status(201).json({ id, ...groupData });
            }
        );
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/groups/user/:email
 * Get all groups for a user
 */
app.get('/api/groups/user/:email', (req, res) => {
    try {
        const { email } = req.params;

        db.all(
            `SELECT DISTINCT g.* FROM groups g
             LEFT JOIN groupMembers gm ON g.id = gm.groupId
             WHERE g.ownerEmail = ? OR gm.userEmail = ?
             ORDER BY g.createdAt DESC`,
            [email, email],
            (err, groups) => {
                if (err) {
                    return res.status(500).json({ error: 'Database error' });
                }
                const normalized = (groups || []).map(g => ({
                    id: g.id,
                    name: g.name,
                    description: g.description,
                    ownerEmail: g.ownerEmail,
                    memberCount: g.memberCount,
                    createdAt: g.createdAt
                }));
                res.json(normalized);
            }
        );
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/groups/user  (no email) - return all groups
 */
app.get('/api/groups/user', (req, res) => {
    try {
        db.all('SELECT * FROM groups ORDER BY createdAt DESC', [], (err, groups) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            const normalized = (groups || []).map(g => ({
                id: g.id,
                name: g.name,
                description: g.description,
                ownerEmail: g.ownerEmail,
                memberCount: g.memberCount,
                createdAt: g.createdAt
            }));
            res.json(normalized);
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/groups/add-member
 */
app.post('/api/groups/add-member', (req, res) => {
    try {
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
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/groups/:id
 */
app.get('/api/groups/:id', (req, res) => {
    try {
        const { id } = req.params;
        db.get('SELECT * FROM groups WHERE id = ?', [id], (err, group) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (!group) return res.status(404).json({ error: 'Group not found' });
            res.json(group);
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * PUT /api/groups/:id
 */
app.put('/api/groups/:id', (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, memberCount } = req.body;
        db.run('UPDATE groups SET name = ?, description = ?, memberCount = ? WHERE id = ?', [name, description, memberCount, id], function(err) {
            if (err) return res.status(500).json({ error: 'Failed to update group' });
            res.json({ message: 'Group updated', id });
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * DELETE /api/groups/:id
 */
app.delete('/api/groups/:id', (req, res) => {
    try {
        const { id } = req.params;
        db.serialize(() => {
            db.run('DELETE FROM groupMessages WHERE groupId = ?', [id]);
            db.run('DELETE FROM groupMembers WHERE groupId = ?', [id]);
            db.run('DELETE FROM groups WHERE id = ?', [id], function(err) {
                if (err) return res.status(500).json({ error: 'Failed to delete group' });
                res.json({ message: 'Group deleted' });
            });
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


// Start server
app.listen(PORT, () => {
    console.log(`EventMatch API Server running on port ${PORT}`);
    console.log(`Local: http://localhost:${PORT}`);
    console.log(`Health Check: http://localhost:${PORT}/api/health`);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) console.error('Error closing database:', err);
        console.log('Database closed. Server shutting down...');
        process.exit(0);
    });
});
