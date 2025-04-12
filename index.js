const express = require('express');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const dotenv = require('dotenv');

dotenv.config();
const app = express();
app.use(express.json());

const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000
});

// Retry logic for DB connection
async function connectWithRetry() {
    let retries = 5;
    while (retries > 0) {
        try {
            await pool.query('SELECT 1');
            console.log('Connected to PostgreSQL');
            break;
        } catch (err) {
            console.error('DB connection failed:', err.message);
            retries -= 1;
            if (retries === 0) throw new Error('Failed to connect to PostgreSQL after retries');
            await new Promise(res => setTimeout(res, 5000)); // Wait 5 seconds
        }
    }
}

// Initialize DB and start server
connectWithRetry()
    .then(() => {
        pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL
            )
        `);

        const opts = {
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: process.env.JWT_SECRET
        };
        passport.use(new JwtStrategy(opts, async (payload, done) => {
            const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [payload.sub]);
            return rows[0] ? done(null, rows[0]) : done(null, false);
        }));

        app.post('/register', async (req, res) => {
            const { username, password } = req.body;
            try {
                const { rows } = await pool.query(
                    'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id',
                    [username, password]
                );
                res.status(201).json({ message: 'User registered', userId: rows[0].id });
            } catch (err) {
                res.status(400).json({ error: 'Username taken' });
            }
        });

        app.post('/login', async (req, res) => {
            const { username, password } = req.body;
            const { rows } = await pool.query('SELECT * FROM users WHERE username = $1 AND password = $2', [username, password]);
            if (!rows[0]) return res.status(401).json({ error: 'Invalid credentials' });

            const token = jwt.sign({ sub: rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.json({ token });
        });

        app.get('/protected', passport.authenticate('jwt', { session: false }), (req, res) => {
            res.json({ message: 'Protected route', user: req.user });
        });

        app.listen(3000, () => console.log('Auth Service running on port 3000'));
    })
    .catch(err => {
        console.error('Startup failed:', err.message);
        process.exit(1);
    });