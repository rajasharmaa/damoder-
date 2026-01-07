// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { connectToDB } = require('./database');
const { ObjectId } = require('mongodb');
const crypto = require('crypto');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const MongoStore = require('connect-mongo');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

let DUMMY_HASH;
(async () => {
  try {
    DUMMY_HASH = await bcrypt.hash('dummy_password_timing_protection', 12);
  } catch (err) {
    console.error('Failed to create dummy hash:', err.message);
    DUMMY_HASH = '$2b$12$' + crypto.randomBytes(32).toString('base64');
  }
})();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isProduction ? 10 : 100,
  message: { error: 'Too many attempts, please try again later' },
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isProduction ? 200 : 2000,
  message: { error: 'Too many requests from this IP' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip
});

const emailCheckLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isProduction ? 30 : 300,
  message: { error: 'Too many email checks, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(helmet({
  contentSecurityPolicy: isProduction ? {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  } : false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  hidePoweredBy: true,
  noSniff: true,
  frameguard: { action: 'deny' }
}));

app.use(xss());
app.use(mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    if (!isProduction) {
      console.warn(`[MongoSanitize] Sanitized ${key} in request`);
    }
  }
}));

if (isProduction) {
  app.set('trust proxy', 1);
}

const allowedOrigins = isProduction ? [
  'https://damoder-traders-x2iy.vercel.app',
  'https://damodertraders.onrender.com'
] : [
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:8080',
  'http://localhost:5174'
];

const corsOptions = {
  origin: function(origin, callback) {
    if (!origin && !isProduction) {
      return callback(null, true);
    }
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      if (!isProduction) {
        console.warn('Blocked CORS for origin:', origin);
      }
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With'],
  exposedHeaders: ['Content-Length', 'X-CSRF-Token'],
  credentials: true,
  maxAge: 86400,
};

app.use(cors(corsOptions));

app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);
app.use('/api/auth/reset-password', authLimiter);
app.use('/api/auth/check-email', emailCheckLimiter);
app.use('/api/auth/validate-password', authLimiter);
app.use('/api', apiLimiter);

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser(process.env.COOKIE_SECRET));

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error('SESSION_SECRET must be at least 32 characters');
  process.exit(1);
}

const sessionConfig = {
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  proxy: isProduction,
  name: 'dt_session_id',
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    ttl: 24 * 60 * 60,
    autoRemove: 'native',
    crypto: {
      secret: process.env.SESSION_SECRET
    },
    collectionName: 'sessions'
  }),
  cookie: {
    secure: isProduction,
    httpOnly: true,
    sameSite: isProduction ? 'none' : 'lax',
    maxAge: 24 * 60 * 60 * 1000,
    path: '/'
  },
  genid: function(req) {
    return crypto.randomBytes(16).toString('hex');
  }
};

app.use(session(sessionConfig));

app.get('/api/csrf-token', (req, res) => {
  try {
    const token = crypto.randomBytes(32).toString('hex');
    req.session.csrfToken = token;
    res.json({ csrfToken: token });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate CSRF token' });
  }
});

app.use((req, res, next) => {
  const path = req.baseUrl + req.path;
  
  const publicEndpoints = [
    '/api/auth/login',
    '/api/auth/register',
    '/api/auth/forgot-password',
    '/api/auth/reset-password',
    '/api/auth/check-email',
    '/api/auth/validate-password'
  ];
  
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  
  if (!safeMethods.includes(req.method) && !publicEndpoints.includes(path)) {
    const clientToken = req.headers['x-csrf-token'];
    const serverToken = req.session.csrfToken;
    
    if (!clientToken || !serverToken || clientToken !== serverToken) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
  }
  
  next();
});

app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: isProduction ? '1d' : 0,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
  }
}));

function isValidObjectId(id) {
  if (!id || typeof id !== 'string') return false;
  return ObjectId.isValid(id) && new ObjectId(id).toString() === id;
}

function sanitizeSearchQuery(query) {
  if (!query || typeof query !== 'string') return '';
  return query.substring(0, 100).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function generateSecureToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function handleError(res, error, context = 'Operation') {
  const errorId = crypto.randomBytes(8).toString('hex');
  
  const logMessage = `${context} error [${errorId}]: ${error.message}`;
  
  if (!isProduction) {
    console.error(logMessage);
    if (error.stack) {
      console.error(error.stack);
    }
  } else {
    console.error(logMessage);
  }
  
  if (error.message && error.message.includes('ObjectId')) {
    return res.status(400).json({ error: 'Invalid ID format' });
  }
  
  if (error.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  
  res.status(500).json({ 
    error: isProduction ? 'Internal server error' : error.message,
    errorId: isProduction ? errorId : undefined
  });
}

async function delayResponse(startTime) {
  const elapsed = Date.now() - startTime;
  const minDelay = 200;
  if (elapsed < minDelay) {
    await new Promise(r => setTimeout(r, minDelay - elapsed));
  }
}

const COMMON_PASSWORDS = [
  'password', '123456', 'qwerty', 'admin', 'welcome', 
  'password123', 'letmein', 'monkey', 'dragon', 'sunshine',
  'master', 'hello', 'freedom', 'whatever', 'qazwsx',
  'trustno1', '654321', 'superman', '1qaz2wsx', 'qwertyuiop',
  '1234567890', '12345678', '123123', '111111', 'passw0rd'
];

function validatePassword(password) {
  if (typeof password !== 'string') {
    return {
      isValid: false,
      validations: {}
    };
  }
  
  const validations = {
    length: password.length >= 8,
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasNumber: /\d/.test(password),
    hasSpecial: /[!@#$%^&*(),.?":{}|<>]/.test(password),
    noSpaces: !/\s/.test(password),
    notCommon: !COMMON_PASSWORDS.includes(password.toLowerCase())
  };
  
  const isValid = Object.values(validations).every(v => v);
  
  return { isValid, validations };
}

function requireUserAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ 
      error: 'Authentication required',
      code: 'UNAUTHORIZED'
    });
  }
  
  next();
}

function requireAdminAuth(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ 
      error: 'Admin access required',
      code: 'FORBIDDEN'
    });
  }
  next();
}

function generateRememberToken() {
  return uuidv4();
}

app.get('/api/auth/check-email', async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { email } = req.query;

    if (!email || typeof email !== 'string') {
      await delayResponse(startTime);
      return res.json({ available: false });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      await delayResponse(startTime);
      return res.json({ available: false });
    }

    const db = await connectToDB();
    const usersCollection = db.collection('users');

    const existingUser = await usersCollection.findOne(
      { email: email.toLowerCase().trim() },
      { projection: { _id: 1 } }
    );

    await bcrypt.compare('dummy_password_timing_protection', DUMMY_HASH);

    await delayResponse(startTime);
    res.json({
      available: !existingUser
    });

  } catch (err) {
    await delayResponse(startTime);
    res.json({ available: false });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email and password are required' });
    }
    
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return res.status(400).json({ 
        error: 'Password does not meet security requirements',
        validations: passwordValidation.validations
      });
    }
    
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    if (name.trim().length < 2 || name.trim().length > 50) {
      return res.status(400).json({ error: 'Name must be between 2 and 50 characters' });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const existingUser = await usersCollection.findOne({ 
      email: email.toLowerCase().trim() 
    });
    
    if (existingUser) {
      await bcrypt.compare('dummy_password_timing_protection', DUMMY_HASH);
      return res.status(400).json({ error: 'Registration failed' });
    }
    
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    const newUser = {
      name: name.trim().substring(0, 50),
      email: email.toLowerCase().trim(),
      phone: phone ? phone.trim().substring(0, 20) : '',
      password: hashedPassword,
      role: 'user',
      createdAt: new Date(),
      updatedAt: new Date(),
      failedLoginAttempts: 0,
      lastLoginAttempt: null,
      lastLogin: null,
      passwordVersion: 1
    };
    
    const result = await usersCollection.insertOne(newUser);
    
    req.session.regenerate((err) => {
      if (err) {
        return handleError(res, err, 'Session creation');
      }
      
      req.session.user = {
        id: result.insertedId.toString(),
        email: newUser.email,
        name: newUser.name,
        role: 'user',
        passwordVersion: newUser.passwordVersion,
        createdAt: Date.now()
      };
      
      usersCollection.updateOne(
        { _id: result.insertedId },
        { $set: { lastLogin: new Date() } }
      ).catch(console.error);
      
      req.session.save((saveErr) => {
        if (saveErr) {
          return handleError(res, saveErr, 'Session save');
        }
        
        res.status(201).json({ 
          message: 'Registration successful',
          user: {
            id: result.insertedId.toString(),
            name: newUser.name,
            email: newUser.email
          }
        });
      });
    });
    
  } catch (err) {
    handleError(res, err, 'Registration');
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const user = await usersCollection.findOne({ 
      email: email.toLowerCase().trim() 
    });
    
    if (!user) {
      await bcrypt.compare('dummy_password_timing_protection', DUMMY_HASH);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const now = new Date();
    const lockoutDuration = 15 * 60 * 1000;
    
    if (user.failedLoginAttempts >= 5 && user.lastLoginAttempt) {
      const timeSinceLastAttempt = now - user.lastLoginAttempt;
      if (timeSinceLastAttempt < lockoutDuration) {
        return res.status(429).json({ 
          error: 'Account temporarily locked. Try again later.',
          retryAfter: Math.ceil((lockoutDuration - timeSinceLastAttempt) / 1000)
        });
      }
    }
    
    const passwordMatch = await bcrypt.compare(password, user.password);
    
    if (!passwordMatch) {
      await usersCollection.updateOne(
        { _id: user._id },
        { 
          $inc: { failedLoginAttempts: 1 },
          $set: { lastLoginAttempt: now }
        }
      );
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (req.session.user && req.session.user.id === user._id.toString()) {
      if (req.session.user.passwordVersion !== user.passwordVersion) {
        req.session.destroy(() => {});
      }
    }
    
    // ✅ FIXED: Generate remember token if rememberMe is true
    let rememberToken = null;
    if (rememberMe === true) {
      rememberToken = generateRememberToken();
      const hashedRememberToken = hashToken(rememberToken);
      const tokenExpiry = Date.now() + (30 * 24 * 60 * 60 * 1000); // 30 days
      
      await usersCollection.updateOne(
        { _id: user._id },
        { 
          $set: { 
            rememberToken: hashedRememberToken,
            rememberTokenExpiry: new Date(tokenExpiry)
          } 
        }
      );
      console.log('✅ Generated remember token for user:', user.email);
    }
    
    req.session.regenerate((err) => {
      if (err) {
        return handleError(res, err, 'Session regeneration');
      }
      
      req.session.user = {
        id: user._id.toString(),
        email: user.email,
        name: user.name,
        role: user.role,
        passwordVersion: user.passwordVersion || 1,
        createdAt: Date.now()
      };
      
      usersCollection.updateOne(
        { _id: user._id },
        { 
          $set: { 
            failedLoginAttempts: 0,
            lastLoginAttempt: null,
            lastLogin: now,
            updatedAt: now
          }
        }
      ).catch(console.error);
      
      req.session.save((saveErr) => {
        if (saveErr) {
          return handleError(res, saveErr, 'Session save');
        }
        
        // ✅ FIXED: Return rememberToken in response
        const response = { 
          message: 'Login successful',
          user: {
            id: user._id.toString(),
            name: user.name,
            email: user.email,
            phone: user.phone
          }
        };
        
        if (rememberToken) {
          response.rememberToken = rememberToken;
        }
        
        console.log('✅ Login successful for user:', user.email);
        res.json(response);
      });
    });
    
  } catch (err) {
    handleError(res, err, 'Login');
  }
});

app.get('/api/auth/status', async (req, res) => {
  try {
    const { rememberToken } = req.query;
    
    // ✅ FIXED: Check remember token first
    if (rememberToken && typeof rememberToken === 'string' && rememberToken.length === 36) {
      console.log('🔄 Checking auth status with remember token');
      const db = await connectToDB();
      const usersCollection = db.collection('users');
      
      const hashedToken = hashToken(rememberToken);
      const user = await usersCollection.findOne({
        rememberToken: hashedToken,
        rememberTokenExpiry: { $gt: new Date() }
      });
      
      if (user) {
        console.log('✅ Valid remember token found for user:', user.email);
        
        req.session.regenerate((err) => {
          if (err) {
            console.error('❌ Session regeneration error:', err);
            return res.json({ authenticated: false });
          }
          
          req.session.user = {
            id: user._id.toString(),
            email: user.email,
            name: user.name,
            role: user.role,
            passwordVersion: user.passwordVersion || 1,
            createdAt: Date.now()
          };
          
          req.session.save((saveErr) => {
            if (saveErr) {
              console.error('❌ Session save error:', saveErr);
              return res.json({ authenticated: false });
            }
            
            console.log('✅ Auto-login via remember token successful');
            res.json({ 
              authenticated: true, 
              user: {
                id: user._id.toString(),
                name: user.name,
                email: user.email,
                role: user.role
              },
              fromRememberToken: true
            });
          });
        });
        return;
      } else {
        console.log('❌ Invalid or expired remember token');
      }
    }
    
    // Check regular session
    if (req.session.user) {
      console.log('✅ User authenticated via session');
      res.json({ 
        authenticated: true, 
        user: {
          id: req.session.user.id,
          name: req.session.user.name,
          email: req.session.user.email,
          role: req.session.user.role
        }
      });
    } else {
      console.log('❌ Not authenticated');
      res.json({ 
        authenticated: false,
        message: 'Not authenticated'
      });
    }
  } catch (err) {
    console.error('❌ Auth status error:', err);
    res.json({ authenticated: false });
  }
});

app.post('/api/auth/refresh-remember-token', requireUserAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    
    if (!isValidObjectId(userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const rememberToken = generateRememberToken();
    const hashedRememberToken = hashToken(rememberToken);
    const tokenExpiry = Date.now() + (30 * 24 * 60 * 60 * 1000);
    
    await usersCollection.updateOne(
      { _id: new ObjectId(userId) },
      { 
        $set: { 
          rememberToken: hashedRememberToken,
          rememberTokenExpiry: new Date(tokenExpiry),
          updatedAt: new Date()
        } 
      }
    );
    
    res.json({ rememberToken });
  } catch (err) {
    handleError(res, err, 'Refresh remember token');
  }
});

app.post('/api/auth/logout', requireUserAuth, async (req, res) => {
  const sessionId = req.sessionID;
  const userId = req.session.user.id;
  
  try {
    if (isValidObjectId(userId)) {
      const db = await connectToDB();
      const usersCollection = db.collection('users');
      await usersCollection.updateOne(
        { _id: new ObjectId(userId) },
        { 
          $unset: { 
            rememberToken: "",
            rememberTokenExpiry: ""
          } 
        }
      );
    }
  } catch (dbErr) {
    console.error('Error clearing remember token:', dbErr.message);
  }
  
  req.session.destroy((err) => {
    if (err) {
      return handleError(res, err, 'Logout');
    }
    
    res.clearCookie('dt_session_id', {
      path: '/',
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      httpOnly: true
    });
    
    if (!isProduction) {
      console.log(`Session ${sessionId} destroyed`);
    }
    
    res.json({ 
      message: 'Logout successful',
      timestamp: new Date().toISOString()
    });
  });
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const user = await usersCollection.findOne({ 
      email: email.toLowerCase().trim() 
    });
    
    if (!user) {
      hashToken('dummy_token_for_timing');
      return res.json({ 
        message: 'If an account exists with this email, you will receive password reset instructions.',
        success: true 
      });
    }
    
    if (user.resetToken && user.resetTokenExpiry && user.resetTokenExpiry > new Date()) {
      return res.status(429).json({ 
        error: 'A password reset has already been requested. Please check your email or wait before requesting another.',
        retryAfter: 300
      });
    }
    
    const resetToken = generateSecureToken();
    const hashedToken = hashToken(resetToken);
    const resetTokenExpiry = Date.now() + 3600000;
    
    await usersCollection.updateOne(
      { _id: user._id },
      { 
        $set: { 
          resetToken: hashedToken,
          resetTokenExpiry: new Date(resetTokenExpiry),
          updatedAt: new Date()
        } 
      }
    );
    
    const resetLink = `${process.env.FRONTEND_URL || 'https://damoder-traders-x2iy.vercel.app'}/reset-password?token=${resetToken}`;
    
    if (!isProduction) {
      console.log('Password reset link:', resetLink);
    }
    
    res.json({ 
      message: 'If an account exists, password reset instructions have been sent.',
      success: true
    });
  } catch (err) {
    handleError(res, err, 'Forgot password');
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    
    if (!token || !password) {
      return res.status(400).json({ error: 'Token and password are required' });
    }
    
    if (typeof token !== 'string' || token.length !== 64) {
      return res.status(400).json({ error: 'Invalid reset token' });
    }
    
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return res.status(400).json({ 
        error: 'Password does not meet security requirements',
        validations: passwordValidation.validations
      });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const hashedToken = hashToken(token);
    
    const user = await usersCollection.findOne({
      resetToken: hashedToken,
      resetTokenExpiry: { $gt: new Date() }
    });
    
    if (!user) {
      await bcrypt.hash('dummy_password_timing_protection', 12);
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    
    const isSamePassword = await bcrypt.compare(password, user.password);
    if (isSamePassword) {
      return res.status(400).json({ error: 'New password must be different from old password' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const newPasswordVersion = (user.passwordVersion || 1) + 1;
    
    await usersCollection.updateOne(
      { _id: user._id },
      { 
        $set: { 
          password: hashedPassword,
          passwordVersion: newPasswordVersion,
          updatedAt: new Date(),
          lastPasswordChange: new Date()
        },
        $unset: {
          resetToken: "",
          resetTokenExpiry: "",
          rememberToken: "",
          rememberTokenExpiry: ""
        }
      }
    );
    
    try {
      const sessionsCollection = db.collection('sessions');
      await sessionsCollection.deleteMany({});
    } catch (sessionErr) {
      console.error('Error invalidating sessions:', sessionErr.message);
    }
    
    res.json({ 
      message: 'Password reset successful. You can now login with your new password.',
      success: true 
    });
  } catch (err) {
    handleError(res, err, 'Reset password');
  }
});

app.post('/api/auth/validate-password', (req, res) => {
  const { password } = req.body;
  
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Password is required' });
  }
  
  const validation = validatePassword(password);
  
  res.json({
    valid: validation.isValid,
    validations: validation.validations
  });
});

app.get('/api/products', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const products = await productsCollection.find({ 
      active: { $ne: false } 
    }).sort({ createdAt: -1 }).limit(100).toArray();
    res.json(products);
  } catch (err) {
    handleError(res, err, 'Fetch products');
  }
});

app.get('/api/products/category/:category', async (req, res) => {
  try {
    const category = sanitizeSearchQuery(req.params.category);
    
    if (!category) {
      return res.status(400).json({ error: 'Category is required' });
    }
    
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const products = await productsCollection.find({ 
      category: { $regex: new RegExp(`^${category}$`, 'i') },
      active: { $ne: false }
    }).sort({ createdAt: -1 }).limit(50).toArray();
    
    res.json(products);
  } catch (err) {
    handleError(res, err, 'Fetch products by category');
  }
});

app.get('/api/products/search', async (req, res) => {
  try {
    let { search, category } = req.query;
    
    search = sanitizeSearchQuery(search);
    category = sanitizeSearchQuery(category);
    
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    
    const query = { active: { $ne: false } };
    
    if (search) {
      try {
        const indexes = await productsCollection.indexes();
        const hasTextIndex = indexes.some(idx => idx.name === 'name_text_description_text_tags_text');
        
        if (hasTextIndex && search.trim().length >= 2) {
          query.$text = { $search: search };
        } else {
          query.$or = [
            { name: { $regex: search, $options: 'i' } },
            { description: { $regex: search, $options: 'i' } },
            { tags: { $regex: search, $options: 'i' } }
          ];
        }
      } catch {
        query.$or = [
          { name: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } },
          { tags: { $regex: search, $options: 'i' } }
        ];
      }
    }
    
    if (category) {
      query.category = { $regex: new RegExp(`^${category}$`, 'i') };
    }
    
    const products = await productsCollection.find(query).sort({ createdAt: -1 }).limit(50).toArray();
    res.json(products);
  } catch (err) {
    handleError(res, err, 'Search products');
  }
});

app.get('/api/products/search/suggestions', async (req, res) => {
  try {
    let { query } = req.query;
    
    if (!query || query.trim().length < 2) {
      return res.json([]);
    }
    
    query = sanitizeSearchQuery(query);
    
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    
    const suggestions = await productsCollection.aggregate([
      {
        $match: {
          active: { $ne: false },
          $or: [
            { name: { $regex: query, $options: 'i' } },
            { category: { $regex: query, $options: 'i' } },
            { tags: { $regex: query, $options: 'i' } }
          ]
        }
      },
      {
        $project: {
          name: 1,
          category: 1,
          _id: 1,
          score: {
            $cond: [
              { $regexMatch: { input: "$name", regex: new RegExp(query, "i") } },
              2,
              1
            ]
          }
        }
      },
      { $sort: { score: -1 } },
      { $limit: 10 }
    ]).toArray();
    
    res.json(suggestions);
  } catch (err) {
    handleError(res, err, 'Fetch suggestions');
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid product ID' });
    }
    
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const product = await productsCollection.findOne({ 
      _id: new ObjectId(req.params.id),
      active: { $ne: false }
    });
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.json(product);
  } catch (err) {
    handleError(res, err, 'Fetch product');
  }
});

app.post('/api/inquiries', async (req, res) => {
  try {
    const { name, email, phone, subject, message } = req.body;
    
    if (!name || !email || !subject || !message) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    if (name.trim().length < 2 || name.trim().length > 100) {
      return res.status(400).json({ error: 'Name must be between 2 and 100 characters' });
    }
    
    if (subject.trim().length < 5 || subject.trim().length > 200) {
      return res.status(400).json({ error: 'Subject must be between 5 and 200 characters' });
    }
    
    if (message.trim().length < 10 || message.trim().length > 2000) {
      return res.status(400).json({ error: 'Message must be between 10 and 2000 characters' });
    }
    
    if (phone && phone.trim().length > 20) {
      return res.status(400).json({ error: 'Phone number is too long' });
    }
    
    const db = await connectToDB();
    const inquiriesCollection = db.collection('inquiries');
    
    const newInquiry = {
      name: name.trim().substring(0, 100),
      email: email.toLowerCase().trim(),
      phone: phone ? phone.trim().substring(0, 20) : '',
      subject: subject.trim().substring(0, 200),
      message: message.trim().substring(0, 2000),
      status: 'new',
      createdAt: new Date(),
      updatedAt: new Date(),
      read: false,
      userId: req.session.user && isValidObjectId(req.session.user.id) 
        ? new ObjectId(req.session.user.id) 
        : null
    };
    
    const result = await inquiriesCollection.insertOne(newInquiry);
    res.status(201).json({ 
      message: 'Inquiry submitted successfully',
      inquiryId: result.insertedId 
    });
  } catch (err) {
    handleError(res, err, 'Create inquiry');
  }
});

app.get('/api/user/inquiries', requireUserAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    
    if (!isValidObjectId(userId)) {
      return res.json([]);
    }
    
    const db = await connectToDB();
    const inquiriesCollection = db.collection('inquiries');
    
    const inquiries = await inquiriesCollection.find({ 
      $or: [
        { userId: new ObjectId(userId) },
        { email: req.session.user.email }
      ]
    }).sort({ createdAt: -1 }).limit(50).toArray();
    
    res.json(inquiries);
  } catch (err) {
    handleError(res, err, 'Fetch user inquiries');
  }
});

app.get('/api/users/:id', requireUserAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    
    if (!isValidObjectId(userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }
    
    if (req.session.user.id !== userId && req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const user = await usersCollection.findOne(
      { _id: new ObjectId(userId) },
      { 
        projection: { 
          password: 0, 
          resetToken: 0, 
          resetTokenExpiry: 0,
          failedLoginAttempts: 0,
          lastLoginAttempt: 0
        } 
      }
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(user);
  } catch (err) {
    handleError(res, err, 'Fetch user profile');
  }
});

app.put('/api/users/:id', requireUserAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    const updates = req.body;
    
    if (!isValidObjectId(userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }
    
    if (req.session.user.id !== userId && req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const allowedUpdates = ['name', 'phone'];
    const updateObj = {};
    
    for (const key of allowedUpdates) {
      if (updates[key] !== undefined) {
        if (key === 'name') {
          if (updates[key].trim().length < 2 || updates[key].trim().length > 50) {
            return res.status(400).json({ error: 'Name must be between 2 and 50 characters' });
          }
          updateObj[key] = updates[key].trim().substring(0, 50);
        } else if (key === 'phone') {
          if (updates[key] && updates[key].trim().length > 20) {
            return res.status(400).json({ error: 'Phone number is too long' });
          }
          updateObj[key] = updates[key] ? updates[key].trim().substring(0, 20) : '';
        }
      }
    }
    
    if (Object.keys(updateObj).length === 0) {
      return res.status(400).json({ error: 'No valid updates provided' });
    }
    
    updateObj.updatedAt = new Date();
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(userId) },
      { $set: updateObj }
    );
    
    if (result.modifiedCount === 0) {
      return res.status(404).json({ error: 'User not found or no changes made' });
    }
    
    if (updateObj.name) {
      req.session.user.name = updateObj.name;
      req.session.save(() => {});
    }
    
    res.json({ 
      message: 'Profile updated successfully',
      updates: updateObj
    });
  } catch (err) {
    handleError(res, err, 'Update user profile');
  }
});

app.get('/api/admin/inquiries', requireUserAuth, requireAdminAuth, async (req, res) => {
  try {
    const { status, limit = 50, page = 1 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const db = await connectToDB();
    const inquiriesCollection = db.collection('inquiries');
    
    const query = {};
    if (status && ['new', 'read', 'replied', 'closed'].includes(status)) {
      query.status = status;
    }
    
    const [inquiries, total] = await Promise.all([
      inquiriesCollection.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .toArray(),
      inquiriesCollection.countDocuments(query)
    ]);
    
    res.json({
      inquiries,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (err) {
    handleError(res, err, 'Fetch admin inquiries');
  }
});

if (!isProduction) {
  app.get('/api/debug/session', requireUserAuth, (req, res) => {
    res.json({
      sessionId: req.sessionID,
      user: req.session.user,
      timestamp: new Date().toISOString(),
      cookies: req.cookies
    });
  });
  
  app.get('/api/debug/db', requireUserAuth, async (req, res) => {
    try {
      const db = await connectToDB();
      const collections = await db.listCollections().toArray();
      const stats = {};
      
      for (const collection of collections) {
        try {
          stats[collection.name] = await db.collection(collection.name).estimatedDocumentCount();
        } catch {
          stats[collection.name] = 'Error';
        }
      }
      
      res.json({
        success: true,
        collections: collections.map(c => c.name),
        stats,
        message: 'Database connection successful'
      });
    } catch (err) {
      handleError(res, err, 'Debug DB');
    }
  });
}

app.get('/api/test', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    nodeVersion: process.version,
    memoryUsage: process.memoryUsage(),
    uptime: process.uptime()
  });
});

app.get('/api/health', async (req, res) => {
  const health = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    service: 'Damodar Traders API',
    version: '3.0.0',
    checks: {}
  };
  
  try {
    const db = await connectToDB();
    await db.command({ ping: 1 });
    health.checks.database = { status: 'OK', latency: Date.now() - new Date(health.timestamp).getTime() };
    
    res.json(health);
  } catch (err) {
    health.status = 'ERROR';
    health.checks.database = { status: 'ERROR', error: err.message };
    res.status(503).json(health);
  }
});

app.get('/api/metrics', requireUserAuth, requireAdminAuth, async (req, res) => {
  try {
    const db = await connectToDB();
    
    const metrics = {
      users: await db.collection('users').estimatedDocumentCount(),
      products: await db.collection('products').estimatedDocumentCount({ active: { $ne: false } }),
      inquiries: await db.collection('inquiries').estimatedDocumentCount(),
      newInquiries: await db.collection('inquiries').estimatedDocumentCount({ status: 'new' }),
      activeSessions: req.sessionStore && typeof req.sessionStore.length === 'function' 
        ? await req.sessionStore.length() 
        : 'N/A'
    };
    
    res.json(metrics);
  } catch (err) {
    handleError(res, err, 'Fetch metrics');
  }
});

app.use((req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found',
    path: req.originalUrl,
    method: req.method
  });
});

app.use((err, req, res, next) => {
  const errorId = crypto.randomBytes(8).toString('hex');
  
  if (!(err.code === 'EBADCSRFTOKEN' && isProduction)) {
    console.error(`Unhandled error [${errorId}]:`, err.message);
    if (!isProduction && err.stack) {
      console.error(err.stack);
    }
  }
  
  const errorResponse = {
    error: isProduction ? 'Internal server error' : err.message,
    code: 'INTERNAL_ERROR',
    timestamp: new Date().toISOString(),
    errorId: isProduction ? errorId : undefined
  };
  
  if (err.code === 'EBADCSRFTOKEN') {
    errorResponse.error = 'Invalid CSRF token';
    errorResponse.code = 'CSRF_ERROR';
    return res.status(403).json(errorResponse);
  }
  
  res.status(err.status || 500).json(errorResponse);
});

const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
  console.log(`Environment: ${isProduction ? 'Production' : 'Development'}`);
  console.log(`CORS Origins: ${allowedOrigins.join(', ')}`);
  
  if (!isProduction) {
    setupDatabaseIndexes().catch(console.error);
  }
});

async function setupDatabaseIndexes() {
  try {
    const db = await connectToDB();
    
    await db.collection('products').createIndex(
      { name: "text", description: "text", tags: "text" },
      { name: "name_text_description_text_tags_text" }
    );
    
    await db.collection('products').createIndex({ active: 1, createdAt: -1 });
    await db.collection('products').createIndex({ category: 1, active: 1 });
    await db.collection('inquiries').createIndex({ userId: 1, createdAt: -1 });
    await db.collection('inquiries').createIndex({ email: 1, createdAt: -1 });
    await db.collection('inquiries').createIndex({ status: 1, createdAt: -1 });
    await db.collection('users').createIndex({ email: 1 }, { unique: true });
    await db.collection('users').createIndex({ resetToken: 1 });
    await db.collection('users').createIndex({ resetTokenExpiry: 1 }, { expireAfterSeconds: 3600 });
    await db.collection('users').createIndex({ rememberToken: 1 });
    await db.collection('users').createIndex({ rememberTokenExpiry: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 });
    
    console.log('✅ Database indexes created/verified');
  } catch (err) {
    console.error('❌ Failed to setup database indexes:', err.message);
  }
}

const shutdown = async (signal) => {
  console.log(`\n${signal} received. Shutting down gracefully...`);
  
  server.close(async () => {
    console.log('HTTP server closed');
  });
  
  const forceExitTimer = setTimeout(() => {
    console.error('Force shutdown after timeout');
    process.exit(1);
  }, 8000);
  
  try {
    const { getClient } = require('./database');
    try {
      const client = getClient();
      if (client && client.close) {
        await client.close(true);
        console.log('MongoDB connections closed');
      }
    } catch (dbErr) {
      console.error('Error closing MongoDB:', dbErr.message);
    }
    
    clearTimeout(forceExitTimer);
    console.log('Shutdown complete');
    process.exit(0);
    
  } catch (err) {
    console.error('Error during shutdown:', err);
    process.exit(1);
  }
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});