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

// Initialize SQLite Database
const dbPath = path.join(__dirname, 'eventmatch.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('Database error:', err);
    else console.log('Connected to SQLite database');
});

// Create users table if not exists
db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);

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
