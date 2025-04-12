const express = require('express');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const morgan = require('morgan');
const cors = require('cors');
const winston = require('winston');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

//app.set('trust proxy', true);
app.set('trust proxy', 1);

// Set up logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

// Apply middleware
app.use(helmet()); // Security headers
app.use(cors()); // Enable CORS
app.use(express.json({ limit: '1mb' })); // Body parser with size limit
app.use(morgan('combined')); // HTTP request logging

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX || '100'), // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', apiLimiter); // Apply rate limiting to all API routes

// Set up database connection
const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    max: parseInt(process.env.DB_MAX_CONNECTIONS || '20'),
    idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT || '30000'),
    connectionTimeoutMillis: parseInt(process.env.DB_CONNECTION_TIMEOUT || '2000'),
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
});

// Wrap PostgreSQL queries to handle errors consistently
const query = async (text, params) => {
  try {
    const start = Date.now();
    const result = await pool.query(text, params);
    const duration = Date.now() - start;
    
    logger.debug({
      query: text,
      params,
      rows: result.rowCount,
      duration
    });
    
    return result;
  } catch (error) {
    logger.error({
      query: text,
      params,
      error: error.message,
      stack: error.stack
    });
    throw error;
  }
};

// Retry logic for DB connection
async function connectWithRetry() {
    let retries = parseInt(process.env.DB_CONNECTION_RETRIES || '5');
    const retryInterval = parseInt(process.env.DB_RETRY_INTERVAL || '5000');
    
    while (retries > 0) {
        try {
            await pool.query('SELECT 1');
            logger.info('Connected to PostgreSQL successfully');
            return true;
        } catch (err) {
            logger.error(`DB connection failed: ${err.message}`);
            retries -= 1;
            if (retries === 0) {
                logger.error('Failed to connect to PostgreSQL after multiple retries');
                throw new Error('Failed to connect to PostgreSQL after multiple retries');
            }
            logger.info(`Retrying in ${retryInterval}ms... (${retries} attempts left)`);
            await new Promise(res => setTimeout(res, retryInterval));
        }
    }
}

// Initialize database schema
async function initializeDatabase() {
    try {
        // Users table with proper password hashing
        await query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY, 
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(60) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP WITH TIME ZONE,
                status VARCHAR(20) DEFAULT 'active',
                role VARCHAR(20) DEFAULT 'user'
            )
        `);

        // Add refresh token table for better auth management
        await query(`
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token VARCHAR(255) NOT NULL,
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                revoked BOOLEAN DEFAULT false,
                device_info TEXT,
                ip_address VARCHAR(45),
                is_remember_me BOOLEAN DEFAULT false,
                UNIQUE(token)
            )
        `);

        // Add failed login attempts tracking
        await query(`
            CREATE TABLE IF NOT EXISTS login_attempts (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                successful BOOLEAN NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        `);

        logger.info('Database schema initialized successfully');
    } catch (error) {
        logger.error(`Database initialization failed: ${error.message}`);
        throw error;
    }
}

// Configure JWT strategy for authentication
function configurePassport() {
    const jwtOptions = {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: process.env.JWT_SECRET,
        algorithms: ['HS256']
    };
    
    passport.use(new JwtStrategy(jwtOptions, async (payload, done) => {
        try {
            // Added verification for token expiration and user status
            if (Date.now() > payload.exp * 1000) {
                return done(null, false, { message: 'Token expired' });
            }
            
            const { rows } = await query(
                'SELECT id, email, role, status FROM users WHERE id = $1',
                [payload.sub]
            );
            
            const user = rows[0];
            if (!user) {
                return done(null, false, { message: 'User not found' });
            }
            
            if (user.status !== 'active') {
                return done(null, false, { message: 'Account is not active' });
            }
            
            return done(null, user);
        } catch (error) {
            return done(error);
        }
    }));
}

// Generate access token
function generateAccessToken(userId, role) {
    return jwt.sign(
        { 
            sub: userId,
            role: role,
            type: 'access'
        },
        process.env.JWT_SECRET,
        { 
            expiresIn: process.env.JWT_ACCESS_EXPIRATION || '1h'
        }
    );
}

// Generate refresh token with rememberMe option
async function generateRefreshToken(userId, isRememberMe = false, deviceInfo = null, ipAddress = null) {
    // Use longer expiration for "remember me" option
    const expiresIn = isRememberMe 
        ? process.env.JWT_REFRESH_REMEMBER_EXPIRATION || '30d'
        : process.env.JWT_REFRESH_EXPIRATION || '7d';
    
    const token = jwt.sign(
        { 
            sub: userId,
            type: 'refresh'
        },
        process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
        { expiresIn }
    );
    
    const decoded = jwt.decode(token);
    const expiresAt = new Date(decoded.exp * 1000);
    
    await query(
        `INSERT INTO refresh_tokens 
        (user_id, token, expires_at, device_info, ip_address, is_remember_me) 
        VALUES ($1, $2, $3, $4, $5, $6)`,
        [userId, token, expiresAt, deviceInfo, ipAddress, isRememberMe]
    );
    
    return token;
}

// Record login attempt
async function recordLoginAttempt(email, ipAddress, userAgent, successful) {
    try {
        await query(
            'INSERT INTO login_attempts (email, ip_address, user_agent, successful) VALUES ($1, $2, $3, $4)',
            [email, ipAddress, userAgent, successful]
        );
    } catch (error) {
        logger.error(`Failed to record login attempt: ${error.message}`);
    }
}

// Common error handler middleware
function errorHandler(err, req, res, next) {
    logger.error({
        message: err.message,
        stack: err.stack,
        path: req.path,
        method: req.method
    });
    
    const statusCode = err.statusCode || 500;
    res.status(statusCode).json({
        error: statusCode === 500 ? 'Internal server error' : err.message
    });
}

// Initialize DB and start server
async function startServer() {
    try {
        // Connect to the database
        await connectWithRetry();
        
        // Initialize database schema
        await initializeDatabase();
        
        // Configure Passport
        configurePassport();
        app.use(passport.initialize());
        
        // API Routes
        setupRoutes();
        
        // Global error handler
        app.use(errorHandler);
        
        // Start the server
        const PORT = process.env.PORT || 3000;
        app.listen(PORT, () => {
            logger.info(`Auth Service running on port ${PORT}`);
        });
    } catch (err) {
        logger.error(`Startup failed: ${err.message}`);
        process.exit(1);
    }
}

// Get device info from request
function getDeviceInfo(req) {
    const userAgent = req.get('User-Agent') || '';
    return {
        userAgent,
        // Add more device identification if available from headers
    };
}

// Set up API routes
function setupRoutes() {
    // Health check route
    app.get('/health', (req, res) => {
        res.status(200).json({ status: 'ok' });
    });
    
    // User registration
    app.post(
        '/api/register',
        [
            body('email')
                .isLength({ min: 3, max: 50 })
                .withMessage('email must be between 3 and 50 characters') 
                .isEmail()
                .withMessage('Must be a valid email address')
                .normalizeEmail(),
            body('password')
                .isLength({ min: 8 })
                .withMessage('Password must be at least 8 characters')
                .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
                .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
                .matches(/[0-9]/).withMessage('Password must contain at least one number') 
        ],
        async (req, res, next) => {
            try {
                // Validate input
                const errors = validationResult(req);
                if (!errors.isEmpty()) {
                    console.log(errors)
                    return res.status(400).json({ errors: errors.array() });
                }

                const { email, password } = req.body;
                
                // Hash password
                const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10');
                const hashedPassword = await bcrypt.hash(password, saltRounds);
                
                // Create user
                const result = await query(
                    'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, role',
                    [email, hashedPassword || null]
                );
                
                res.status(201).json({
                    message: 'User registered successfully',
                    user: {
                        id: result.rows[0].id,
                        email: result.rows[0].email, 
                        role: result.rows[0].role
                    }
                });
            } catch (err) {
                // Handle duplicate key violations specifically
                if (err.code === '23505') { // Postgres unique violation
                      if (err.constraint === 'users_email_key') {
                        return res.status(409).json({ error: 'Email is already registered' });
                    }
                }
                next(err);
            }
        }
    );

    // User login with remember me option
    app.post(
        '/api/login',
        [
            body('email').notEmpty().withMessage('email is required'),
            body('password').notEmpty().withMessage('Password is required'),
            body('rememberMe').optional().isBoolean().withMessage('Remember me must be a boolean')
        ],
        async (req, res, next) => {
            try {
                // Validate input
                const errors = validationResult(req);
                if (!errors.isEmpty()) {
                    return res.status(400).json({ errors: errors.array() });
                }

                const { email, password, rememberMe = false } = req.body;
                const ipAddress = req.ip;
                const userAgent = req.get('User-Agent');
                const deviceInfo = JSON.stringify(getDeviceInfo(req));
                
                // Get user
                const { rows } = await query(
                    'SELECT * FROM users WHERE email = $1',
                    [email]
                );
                
                const user = rows[0];
                
                // Check if user exists and password is correct
                if (!user || !(await bcrypt.compare(password, user.password))) {
                    await recordLoginAttempt(email, ipAddress, userAgent, false);
                    return res.status(401).json({ error: 'Invalid credentials' });
                }
                
                // Check if user is active
                if (user.status !== 'active') {
                    await recordLoginAttempt(email, ipAddress, userAgent, false);
                    return res.status(403).json({ error: 'Account is not active' });
                }
                
                // Update last login time
                await query(
                    'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
                    [user.id]
                );
                
                // Record successful login
                await recordLoginAttempt(email, ipAddress, userAgent, true);
                
                // Generate tokens with remember me setting
                const accessToken = generateAccessToken(user.id, user.role);
                const refreshToken = await generateRefreshToken(
                    user.id, 
                    rememberMe, 
                    deviceInfo, 
                    ipAddress
                );
                
                // Calculate token expiry time
                const accessExpiry = process.env.JWT_ACCESS_EXPIRATION || '1h';
                const refreshExpiry = rememberMe
                    ? process.env.JWT_REFRESH_REMEMBER_EXPIRATION || '30d'
                    : process.env.JWT_REFRESH_EXPIRATION || '7d';
                
                res.json({
                    message: 'Login successful',
                    user: {
                        id: user.id,
                        email: user.email, 
                        role: user.role
                    },
                    tokens: {
                        access: accessToken,
                        refresh: refreshToken,
                        accessExpiresIn: accessExpiry,
                        refreshExpiresIn: refreshExpiry,
                        rememberMe
                    }
                });
            } catch (err) {
                next(err);
            }
        }
    );

    // Refresh token
    app.post(
        '/api/refresh-token',
        [
            body('refreshToken').notEmpty().withMessage('Refresh token is required')
        ],
        async (req, res, next) => {
            try {
                const { refreshToken } = req.body;
                const ipAddress = req.ip;
                const deviceInfo = JSON.stringify(getDeviceInfo(req));
                
                // Verify refresh token
                let payload;
                try {
                    payload = jwt.verify(
                        refreshToken,
                        process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET
                    );
                } catch (err) {
                    return res.status(401).json({ error: 'Invalid refresh token' });
                }
                
                // Check if token exists and is not revoked
                const tokenResult = await query(
                    'SELECT * FROM refresh_tokens WHERE token = $1 AND revoked = false AND expires_at > CURRENT_TIMESTAMP',
                    [refreshToken]
                );
                
                if (tokenResult.rows.length === 0) {
                    return res.status(401).json({ error: 'Refresh token invalid or expired' });
                }
                
                const storedToken = tokenResult.rows[0];
                
                // Get user
                const userResult = await query(
                    'SELECT id, email, role, status FROM users WHERE id = $1',
                    [payload.sub]
                );
                
                const user = userResult.rows[0];
                
                // Check if user exists and is active
                if (!user || user.status !== 'active') {
                    return res.status(401).json({ error: 'User not found or inactive' });
                }
                
                // Generate new tokens - maintain the remember me setting
                const accessToken = generateAccessToken(user.id, user.role);
                const newRefreshToken = await generateRefreshToken(
                    user.id,
                    storedToken.is_remember_me,
                    deviceInfo,
                    ipAddress
                );
                
                // Revoke old refresh token
                await query(
                    'UPDATE refresh_tokens SET revoked = true WHERE token = $1',
                    [refreshToken]
                );
                
                // Calculate token expiry times
                const accessExpiry = process.env.JWT_ACCESS_EXPIRATION || '1h';
                const refreshExpiry = storedToken.is_remember_me
                    ? process.env.JWT_REFRESH_REMEMBER_EXPIRATION || '30d'
                    : process.env.JWT_REFRESH_EXPIRATION || '7d';
                
                res.json({
                    tokens: {
                        access: accessToken,
                        refresh: newRefreshToken,
                        accessExpiresIn: accessExpiry,
                        refreshExpiresIn: refreshExpiry,
                        rememberMe: storedToken.is_remember_me
                    }
                });
            } catch (err) {
                next(err);
            }
        }
    );

    // Logout
    app.post(
        '/api/logout',
        [
            body('refreshToken').notEmpty().withMessage('Refresh token is required')
        ],
        async (req, res, next) => {
            try {
                const { refreshToken } = req.body;
                
                // Revoke refresh token
                await query(
                    'UPDATE refresh_tokens SET revoked = true WHERE token = $1',
                    [refreshToken]
                );
                
                res.json({ message: 'Logged out successfully' });
            } catch (err) {
                next(err);
            }
        }
    );

    // Logout from all devices
    app.post(
        '/api/logout-all',
        passport.authenticate('jwt', { session: false }),
        async (req, res, next) => {
            try {
                const userId = req.user.id;
                
                // Revoke all refresh tokens for the user
                await query(
                    'UPDATE refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false',
                    [userId]
                );
                
                res.json({ message: 'Logged out from all devices successfully' });
            } catch (err) {
                next(err);
            }
        }
    );

    // List active sessions
    app.get(
        '/api/active-sessions',
        passport.authenticate('jwt', { session: false }),
        async (req, res, next) => {
            try {
                const userId = req.user.id;
                
                // Get all active refresh tokens for the user
                const { rows } = await query(
                    `SELECT id, created_at, expires_at, device_info, ip_address, is_remember_me 
                    FROM refresh_tokens 
                    WHERE user_id = $1 AND revoked = false AND expires_at > CURRENT_TIMESTAMP
                    ORDER BY created_at DESC`,
                    [userId]
                );
                
                // Format the sessions data
                const sessions = rows.map(session => {
                    let deviceData = { userAgent: 'Unknown' };
                    try {
                        if (session.device_info) {
                            deviceData = JSON.parse(session.device_info);
                        }
                    } catch (e) {
                        logger.error(`Failed to parse device info: ${e.message}`);
                    }
                    
                    return {
                        id: session.id,
                        createdAt: session.created_at,
                        expiresAt: session.expires_at,
                        ipAddress: session.ip_address,
                        userAgent: deviceData.userAgent,
                        isRememberMe: session.is_remember_me
                    };
                });
                
                res.json({ sessions });
            } catch (err) {
                next(err);
            }
        }
    );

    // Revoke specific session
    app.delete(
        '/api/sessions/:sessionId',
        passport.authenticate('jwt', { session: false }),
        async (req, res, next) => {
            try {
                const userId = req.user.id;
                const sessionId = req.params.sessionId;
                
                // Revoke the specific token and ensure it belongs to the current user
                const result = await query(
                    'UPDATE refresh_tokens SET revoked = true WHERE id = $1 AND user_id = $2 RETURNING id',
                    [sessionId, userId]
                );
                
                if (result.rows.length === 0) {
                    return res.status(404).json({ error: 'Session not found or already revoked' });
                }
                
                res.json({ message: 'Session revoked successfully' });
            } catch (err) {
                next(err);
            }
        }
    );

    // Protected route example
    app.get(
        '/api/profile',
        passport.authenticate('jwt', { session: false }),
        (req, res) => {
            res.json({
                message: 'Protected profile route',
                user: {
                    id: req.user.id,
                    email: req.user.email, 
                    role: req.user.role
                }
            });
        }
    );

    // Admin only route example
    app.get(
        '/api/admin',
        passport.authenticate('jwt', { session: false }),
        (req, res) => {
            if (req.user.role !== 'admin') {
                return res.status(403).json({ error: 'Access denied. Admin role required.' });
            }
            
            res.json({
                message: 'Admin route access granted',
                user: req.user
            });
        }
    );

    // Password change route
    app.put(
        '/api/change-password',
        passport.authenticate('jwt', { session: false }),
        [
            body('currentPassword').notEmpty().withMessage('Current password is required'),
            body('newPassword')
                .isLength({ min: 8 })
                .withMessage('Password must be at least 8 characters')
                .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
                .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
                .matches(/[0-9]/).withMessage('Password must contain at least one number')
        ],
        async (req, res, next) => {
            try {
                // Validate input
                const errors = validationResult(req);
                if (!errors.isEmpty()) {
                    return res.status(400).json({ errors: errors.array() });
                }

                const { currentPassword, newPassword } = req.body;
                const userId = req.user.id;
                
                // Get user with password
                const { rows } = await query(
                    'SELECT * FROM users WHERE id = $1',
                    [userId]
                );
                
                const user = rows[0];
                
                // Verify current password
                if (!(await bcrypt.compare(currentPassword, user.password))) {
                    return res.status(401).json({ error: 'Current password is incorrect' });
                }
                
                // Hash new password
                const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10');
                const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
                
                // Update password
                await query(
                    'UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
                    [hashedPassword, userId]
                );
                
                // Optional: invalidate all existing sessions when password changes
                if (process.env.INVALIDATE_SESSIONS_ON_PASSWORD_CHANGE === 'true') {
                    await query(
                        'UPDATE refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false',
                        [userId]
                    );
                    
                    return res.json({ 
                        message: 'Password updated successfully. All existing sessions have been invalidated.'
                    });
                }
                
                res.json({ message: 'Password updated successfully' });
            } catch (err) {
                next(err);
            }
        }
    );

    // Update user profile
    app.put(
        '/api/profile',
        passport.authenticate('jwt', { session: false }),
        [
            body('email')
                .optional()
                .isEmail()
                .withMessage('Must be a valid email address')
                .normalizeEmail()
        ],
        async (req, res, next) => {
            try {
                // Validate input
                const errors = validationResult(req);
                if (!errors.isEmpty()) {
                    return res.status(400).json({ errors: errors.array() });
                }

                const { email } = req.body;
                const userId = req.user.id;
                
                // Update profile
                await query(
                    'UPDATE users SET email = COALESCE($1, email), updated_at = CURRENT_TIMESTAMP WHERE id = $2',
                    [email, userId]
                );
                
                // Get updated user data
                const { rows } = await query(
                    'SELECT id, email,   role FROM users WHERE id = $1',
                    [userId]
                );
                
                res.json({
                    message: 'Profile updated successfully',
                    user: rows[0]
                });
            } catch (err) {
                // Handle duplicate email
                if (err.code === '23505' && err.constraint === 'users_email_key') {
                    return res.status(409).json({ error: 'Email is already registered' });
                }
                next(err);
            }
        }
    );
}

// Start the server
startServer();

// Handle graceful shutdown
process.on('SIGTERM', async () => {
    logger.info('SIGTERM received, shutting down gracefully');
    await pool.end();
    process.exit(0);
});

process.on('SIGINT', async () => {
    logger.info('SIGINT received, shutting down gracefully');
    await pool.end();
    process.exit(0);
});

// Export for testing
module.exports = { app, pool, query };