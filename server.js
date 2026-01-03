// server.js - Complete Persistent Session Backend
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const cookieParser = require('cookie-parser');
const { connectToDB } = require('./database');
const { ObjectId } = require('mongodb');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for production
const isProduction = process.env.NODE_ENV === 'production';
if (isProduction) {
  app.set('trust proxy', 1);
}

// Enhanced CORS configuration
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:5174',
  'http://127.0.0.1:5500',
  'http://localhost:3001',
  'http://localhost:8080',
  'https://damoder-traders-x2iy.vercel.app',
  'https://damodertraders.onrender.com',
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin && !isProduction) {
      return callback(null, true);
    }
    
    if (allowedOrigins.indexOf(origin) !== -1 || 
        (origin && origin.includes('localhost')) ||
        (origin && origin.endsWith('.vercel.app'))) {
      callback(null, true);
    } else {
      console.log('⚠️ Blocked CORS for origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'Accept',
    'Origin',
    'X-Requested-With',
    'X-Client',
    'X-Client-Version',
    'X-Session-Refresh',
    'Cache-Control',
    'Expires',
    'Pragma'
  ],
  exposedHeaders: ['Content-Length', 'X-Total-Count', 'Set-Cookie'],
  credentials: true,
  maxAge: 86400,
  preflightContinue: false,
  optionsSuccessStatus: 204
}));

// Handle preflight requests
app.options('*', cors());

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Session configuration with MongoDB store
const sessionConfig = {
  secret: process.env.SESSION_SECRET || 'damodar-traders-secure-session-secret-2024',
  resave: false,
  saveUninitialized: false,
  proxy: isProduction,
  name: 'dt_session_id',
  rolling: true, // Extend session on activity
  cookie: {
    secure: isProduction,
    httpOnly: true,
    sameSite: isProduction ? 'none' : 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days default
    path: '/',
    ...(isProduction && {
      domain: '.damodertraders.onrender.com',
    }),
  },
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'user_sessions',
    ttl: 30 * 24 * 60 * 60, // 30 days
    autoRemove: 'native',
    crypto: {
      secret: process.env.SESSION_SECRET || 'damodar-session-secret'
    },
    touchAfter: 24 * 3600, // Only update once per day unless modified
  }),
};

// Log session config
console.log('Session Configuration:', {
  isProduction,
  store: 'MongoDB',
  cookieMaxAge: '30 days',
  cookieSecure: sessionConfig.cookie.secure,
  cookieSameSite: sessionConfig.cookie.sameSite,
  rollingSessions: true,
});

app.use(session(sessionConfig));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Helper functions
function isValidObjectId(id) {
  if (!id) return false;
  return /^[0-9a-fA-F]{24}$/.test(id);
}

function createSession(req, user, rememberMe = false) {
  req.session.user = {
    id: user._id.toString(),
    email: user.email,
    name: user.name,
    role: user.role,
    avatar: user.avatar,
    phone: user.phone,
  };
  
  // Set longer maxAge for "remember me"
  if (rememberMe) {
    req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
  } else {
    req.session.cookie.maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days
  }
  
  // Update session in store
  req.session.touch();
}

// Authentication middleware
function requireUserAuth(req, res, next) {
  console.log('🔐 Auth check:', {
    hasSession: !!req.session.user,
    sessionId: req.sessionID,
    path: req.path,
  });
  
  if (!req.session.user) {
    console.log('❌ No user in session');
    return res.status(401).json({
      authenticated: false,
      error: 'Unauthorized - Please login first',
      code: 'SESSION_EXPIRED'
    });
  }
  
  console.log('✅ User authenticated:', req.session.user.email);
  next();
}

// ==================== ENHANCED AUTH ENDPOINTS ====================

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    service: 'Damodar Traders API',
    version: '2.1.0',
    session: {
      hasUser: !!req.session.user,
      id: req.sessionID,
      store: 'MongoDB',
    },
    features: ['persistent-sessions', 'mongodb-store', 'auto-refresh'],
  });
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    session: {
      id: req.sessionID,
      hasUser: !!req.session.user,
    },
    message: 'API is working correctly',
  });
});

// Auth status
app.get('/api/auth/status', (req, res) => {
  console.log('=== Auth Status Check ===');
  console.log('Session ID:', req.sessionID);
  console.log('Session user:', req.session.user);
  
  if (req.session.user) {
    // Update last activity
    req.session.touch();
    
    res.json({
      authenticated: true,
      user: {
        id: req.session.user.id,
        name: req.session.user.name,
        email: req.session.user.email,
        role: req.session.user.role,
        phone: req.session.user.phone,
        avatar: req.session.user.avatar,
      },
      session: {
        expires: new Date(Date.now() + req.session.cookie.maxAge).toISOString(),
        maxAge: req.session.cookie.maxAge,
      },
    });
  } else {
    res.json({
      authenticated: false,
      message: 'Not authenticated',
    });
  }
});

// Login with persistent sessions
app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('=== LOGIN ATTEMPT ===');
    console.log('Email:', req.body.email);
    console.log('Remember me:', req.body.rememberMe);
    
    const { email, password, rememberMe = false } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password are required',
      });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    // Find user
    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'User not found. Please register first.',
      });
    }
    
    // Check password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        error: 'Invalid password. Please try again.',
      });
    }
    
    // Create session
    createSession(req, user, rememberMe);
    
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({
          success: false,
          error: 'Failed to create session',
        });
      }
      
      console.log('✅ Login successful for:', user.email);
      console.log('Session maxAge:', req.session.cookie.maxAge);
      
      res.json({
        success: true,
        message: 'Login successful',
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          phone: user.phone,
          role: user.role,
          avatar: user.avatar,
        },
        session: {
          expiresAt: new Date(Date.now() + req.session.cookie.maxAge).toISOString(),
          maxAge: req.session.cookie.maxAge,
          persistent: rememberMe,
        },
      });
    });
    
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({
      success: false,
      error: 'Login failed. Please try again.',
      details: isProduction ? undefined : err.message,
    });
  }
});

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    
    console.log('Registration attempt:', { name, email });
    
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Name, email and password are required',
      });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    // Check if user exists
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'User already exists',
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = {
      name,
      email,
      phone: phone || '',
      password: hashedPassword,
      role: 'user',
      avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=random`,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastLogin: new Date(),
    };
    
    const result = await usersCollection.insertOne(newUser);
    
    // Create session
    createSession(req, { ...newUser, _id: result.insertedId }, false);
    
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({
          success: false,
          error: 'Registration successful but failed to create session',
        });
      }
      
      console.log('✅ Registration successful for:', newUser.email);
      
      res.status(201).json({
        success: true,
        message: 'Registration successful',
        user: {
          id: result.insertedId,
          name: newUser.name,
          email: newUser.email,
          phone: newUser.phone,
          role: newUser.role,
          avatar: newUser.avatar,
        },
      });
    });
    
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({
      success: false,
      error: 'Registration failed',
    });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  console.log('=== LOGOUT ===');
  console.log('User:', req.session.user?.email);
  
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({
        success: false,
        error: 'Logout failed',
      });
    }
    
    res.clearCookie('dt_session_id', {
      path: '/',
      domain: isProduction ? '.damodertraders.onrender.com' : undefined,
    });
    
    console.log('✅ Logout successful');
    res.json({
      success: true,
      message: 'Logout successful',
    });
  });
});

// Session refresh
app.post('/api/auth/refresh-session', requireUserAuth, (req, res) => {
  try {
    console.log('=== SESSION REFRESH ===');
    console.log('User:', req.session.user.email);
    console.log('Current maxAge:', req.session.cookie.maxAge);
    
    // Touch the session to reset maxAge
    req.session.touch();
    
    // Determine new maxAge based on current session
    const currentMaxAge = req.session.cookie.maxAge;
    const isPersistent = currentMaxAge >= 30 * 24 * 60 * 60 * 1000; // 30 days
    
    // Extend session (30 days for persistent, 7 days for regular)
    const newMaxAge = isPersistent 
      ? 30 * 24 * 60 * 60 * 1000 
      : 7 * 24 * 60 * 60 * 1000;
    
    req.session.cookie.maxAge = newMaxAge;
    
    req.session.save((err) => {
      if (err) {
        console.error('Session refresh error:', err);
        return res.status(500).json({
          success: false,
          error: 'Failed to refresh session',
        });
      }
      
      console.log('✅ Session refreshed');
      console.log('New maxAge:', newMaxAge);
      
      res.json({
        success: true,
        message: 'Session refreshed',
        session: {
          expiresAt: new Date(Date.now() + newMaxAge).toISOString(),
          maxAge: newMaxAge,
          persistent: isPersistent,
        },
      });
    });
  } catch (err) {
    console.error('Session refresh error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to refresh session',
    });
  }
});

// Keep-alive endpoint (doesn't require auth)
app.get('/api/auth/keep-alive', (req, res) => {
  if (req.session.user) {
    // Just touch the session to keep it alive
    req.session.touch();
    console.log('💓 Keep-alive for:', req.session.user.email);
  }
  
  res.json({
    success: true,
    status: 'ok',
    timestamp: new Date().toISOString(),
    user: req.session.user ? 'authenticated' : 'anonymous',
  });
});

// Session info endpoint
app.get('/api/auth/session-info', requireUserAuth, (req, res) => {
  res.json({
    success: true,
    session: {
      id: req.sessionID,
      user: req.session.user,
      cookie: {
        maxAge: req.session.cookie.maxAge,
        expires: req.session.cookie.expires,
        originalMaxAge: req.session.cookie.originalMaxAge,
        secure: req.session.cookie.secure,
        sameSite: req.session.cookie.sameSite,
        httpOnly: req.session.cookie.httpOnly,
      },
      store: 'mongodb',
      createdAt: req.session.createdAt,
      lastActivity: new Date(),
    },
    timestamp: new Date().toISOString(),
    timeRemaining: Math.round(req.session.cookie.maxAge / 1000 / 60 / 60) + ' hours',
  });
});

// Check email
app.get('/api/auth/check-email', async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({
        exists: false,
        message: 'Email is required',
      });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const user = await usersCollection.findOne({ email });
    
    res.json({
      exists: !!user,
      message: user ? 'Account exists' : 'No account found',
      user: user ? {
        id: user._id,
        name: user.name,
        email: user.email,
        hasAccount: true,
      } : null,
    });
  } catch (err) {
    console.error('Error checking email:', err);
    res.status(500).json({
      exists: false,
      message: 'Error checking email',
      error: err.message,
    });
  }
});

// Forgot password
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const user = await usersCollection.findOne({ email });
    
    if (!user) {
      // Return success even if user doesn't exist (security)
      return res.json({
        success: true,
        message: 'If an account exists with this email, you will receive password reset instructions.',
      });
    }
    
    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour
    
    await usersCollection.updateOne(
      { _id: user._id },
      {
        $set: {
          resetToken,
          resetTokenExpiry: new Date(resetTokenExpiry),
        },
      }
    );
    
    // In production, send email here
    const resetLink = `${process.env.FRONTEND_URL || 'https://damoder-traders-x2iy.vercel.app'}/reset-password?token=${resetToken}`;
    
    console.log('Password reset link:', resetLink); // For development
    
    res.json({
      success: true,
      message: 'Password reset instructions sent to your email.',
      // For development only
      development: { resetLink },
    });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Failed to process password reset request' });
  }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    
    if (!token || !password) {
      return res.status(400).json({ error: 'Token and password are required' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const user = await usersCollection.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: new Date() },
    });
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    await usersCollection.updateOne(
      { _id: user._id },
      {
        $set: {
          password: hashedPassword,
          updatedAt: new Date(),
        },
        $unset: {
          resetToken: '',
          resetTokenExpiry: '',
        },
      }
    );
    
    res.json({
      success: true,
      message: 'Password reset successful. You can now login with your new password.',
    });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Validate password strength
app.post('/api/auth/validate-password', (req, res) => {
  const { password } = req.body;
  
  const validations = {
    length: password.length >= 6,
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasNumber: /\d/.test(password),
    hasSpecial: /[!@#$%^&*(),.?":{}|<>]/.test(password),
  };
  
  const isValid = Object.values(validations).every(v => v);
  
  res.json({
    valid: isValid,
    validations,
    score: Object.values(validations).filter(v => v).length,
  });
});

// ==================== PRODUCT ENDPOINTS ====================

// Get all products
app.get('/api/products', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const products = await productsCollection.find().sort({ createdAt: -1 }).toArray();
    res.json(products);
  } catch (err) {
    console.error('Error fetching products:', err);
    res.json([]);
  }
});

// Get products by category
app.get('/api/products/category/:category', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const products = await productsCollection.find({
      category: req.params.category,
    }).sort({ createdAt: -1 }).toArray();
    res.json(products);
  } catch (err) {
    console.error('Error fetching products by category:', err);
    res.json([]);
  }
});

// Search products
app.get('/api/products/search', async (req, res) => {
  try {
    const { search, category } = req.query;
    
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    
    const query = {};
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { category: { $regex: search, $options: 'i' } },
        { material: { $regex: search, $options: 'i' } },
      ];
    }
    
    if (category) {
      query.category = { $regex: new RegExp(`^${category}$`, 'i') };
    }
    
    const products = await productsCollection.find(query).sort({ createdAt: -1 }).toArray();
    res.json(products);
  } catch (err) {
    console.error('Error searching products:', err);
    res.json([]);
  }
});

// Get search suggestions
app.get('/api/products/search/suggestions', async (req, res) => {
  try {
    const { query } = req.query;
    
    if (!query || query.trim().length < 2) {
      return res.json([]);
    }
    
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    
    const suggestions = await productsCollection.aggregate([
      {
        $match: {
          $or: [
            { name: { $regex: query, $options: 'i' } },
            { category: { $regex: query, $options: 'i' } },
            { material: { $regex: query, $options: 'i' } },
          ],
        },
      },
      {
        $project: {
          name: 1,
          category: 1,
          _id: 1,
          score: {
            $add: [
              {
                $cond: [
                  { $regexMatch: { input: '$name', regex: new RegExp(query, 'i') } },
                  10,
                  0,
                ],
              },
              {
                $cond: [
                  { $regexMatch: { input: '$category', regex: new RegExp(query, 'i') } },
                  5,
                  0,
                ],
              },
              {
                $cond: [
                  { $regexMatch: { input: '$material', regex: new RegExp(query, 'i') } },
                  3,
                  0,
                ],
              },
            ],
          },
        },
      },
      { $sort: { score: -1 } },
      { $limit: 10 },
    ]).toArray();
    
    res.json(suggestions);
  } catch (err) {
    console.error('Error fetching search suggestions:', err);
    res.json([]);
  }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
  try {
    if (!isValidObjectId(req.params.id)) {
      return res.json(null);
    }
    
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const product = await productsCollection.findOne({
      _id: new ObjectId(req.params.id),
    });
    
    res.json(product || null);
  } catch (err) {
    console.error('Error fetching product:', err);
    res.json(null);
  }
});

// Get discounted products
app.get('/api/products/discounted', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    
    const discountedProducts = await productsCollection.find({
      discount: { $exists: true, $ne: null, $gt: 0 },
    }).sort({ discount: -1 }).limit(10).toArray();
    
    res.json(discountedProducts || []);
  } catch (err) {
    console.error('Error fetching discounted products:', err);
    res.json([]);
  }
});

// Get popular products
app.get('/api/products/popular', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    
    const popularProducts = await productsCollection.find({
      discount: { $exists: true, $ne: null, $gt: 0 },
    }).sort({ discount: -1 }).limit(10).toArray();
    
    res.json(popularProducts || []);
  } catch (err) {
    console.error('Error fetching popular products:', err);
    res.json([]);
  }
});

// ==================== USER ENDPOINTS ====================

// Get user profile
app.get('/api/users/:id', requireUserAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.id)) {
      return res.json(null);
    }
    
    if (req.session.user.id !== req.params.id && req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const user = await usersCollection.findOne(
      { _id: new ObjectId(req.params.id) },
      { projection: { password: 0 } }
    );
    
    res.json(user || null);
  } catch (err) {
    console.error('Error fetching user:', err);
    res.json(null);
  }
});

// Update user profile
app.put('/api/users/:id', requireUserAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }
    
    if (req.session.user.id !== req.params.id && req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const updateData = {
      name: req.body.name,
      phone: req.body.phone,
      updatedAt: new Date(),
    };
    
    if (req.body.password) {
      updateData.password = await bcrypt.hash(req.body.password, 10);
    }
    
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: updateData }
    );
    
    if (result.modifiedCount === 0) {
      return res.status(400).json({ error: 'No changes made' });
    }
    
    // Update session if name changed
    if (req.body.name && req.session.user) {
      req.session.user.name = req.body.name;
    }
    
    const updatedUser = await usersCollection.findOne(
      { _id: new ObjectId(req.params.id) },
      { projection: { password: 0 } }
    );
    
    res.json(updatedUser);
  } catch (err) {
    console.error('Error updating user:', err);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// ==================== INQUIRY ENDPOINTS ====================

// Create inquiry
app.post('/api/inquiries', async (req, res) => {
  try {
    const db = await connectToDB();
    const inquiriesCollection = db.collection('inquiries');
    
    const newInquiry = {
      name: req.body.name,
      email: req.body.email,
      phone: req.body.phone,
      subject: req.body.subject,
      message: req.body.message,
      status: 'new',
      createdAt: new Date(),
      read: false,
      userId: req.body.userId || null,
    };
    
    const result = await inquiriesCollection.insertOne(newInquiry);
    
    res.status(201).json({
      ...newInquiry,
      _id: result.insertedId,
      message: 'Inquiry submitted successfully',
    });
  } catch (err) {
    console.error('Error creating inquiry:', err);
    res.status(500).json({ error: 'Failed to submit inquiry' });
  }
});

// Get user inquiries
app.get('/api/user/inquiries', requireUserAuth, async (req, res) => {
  try {
    console.log('Getting inquiries for user:', req.session.user.id);
    
    if (!isValidObjectId(req.session.user.id)) {
      return res.json([]);
    }
    
    const db = await connectToDB();
    const inquiriesCollection = db.collection('inquiries');
    
    const inquiries = await inquiriesCollection
      .find({
        $or: [
          { userId: new ObjectId(req.session.user.id) },
          { email: req.session.user.email },
        ],
      })
      .sort({ createdAt: -1 })
      .toArray();
    
    console.log(`Found ${inquiries.length} inquiries`);
    res.json(inquiries);
  } catch (err) {
    console.error('Error fetching user inquiries:', err);
    res.json([]);
  }
});

// ==================== DEBUG ENDPOINTS ====================

// Debug session
app.get('/api/debug/session', (req, res) => {
  res.json({
    sessionId: req.sessionID,
    session: req.session,
    user: req.session.user,
    cookies: req.cookies,
    headers: {
      origin: req.headers.origin,
      cookie: req.headers.cookie,
    },
    timestamp: new Date().toISOString(),
  });
});

// Debug cookies
app.get('/api/debug/cookies', (req, res) => {
  res.json({
    cookies: req.cookies,
    sessionId: req.sessionID,
    session: req.session,
    headers: {
      origin: req.headers.origin,
      cookie: req.headers.cookie,
      'user-agent': req.headers['user-agent'],
    },
  });
});

// Debug database
app.get('/api/debug/db', async (req, res) => {
  try {
    const db = await connectToDB();
    const collections = await db.listCollections().toArray();
    
    res.json({
      success: true,
      collections: collections.map(c => c.name),
      message: 'Database connection successful',
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message,
      message: 'Database connection failed',
    });
  }
});

// ==================== SERVER STARTUP ====================

app.listen(PORT, async () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║           DAMODAR TRADERS SERVER v2.1.0                  ║
║           PERSISTENT SESSIONS ENABLED                   ║
╚══════════════════════════════════════════════════════════╝
  
  🚀 Server running on port: ${PORT}
  🌍 Environment: ${process.env.NODE_ENV || 'development'}
  📁 Static files: ${path.join(__dirname, 'public')}
  🔧 API Base URL: http://localhost:${PORT}/api
  
  🔐 SESSION CONFIGURATION:
  ├── Store: MongoDB
  ├── Cookie maxAge: 30 days (persistent)
  ├── Cookie secure: ${isProduction}
  ├── Cookie sameSite: ${isProduction ? 'none' : 'lax'}
  ├── Rolling sessions: Enabled
  └── Auto-refresh: Enabled
  
  📊 FEATURES:
  ├── Persistent user sessions (30 days)
  ├── MongoDB session store
  ├── Auto session refresh
  ├── Keep-alive endpoints
  ├── LocalStorage fallback
  ├── Offline support
  └── Cross-tab sync
  
  🔐 AUTH ENDPOINTS:
  ├── /api/auth/login        - Login with remember me
  ├── /api/auth/register     - Register new user
  ├── /api/auth/logout       - Logout
  ├── /api/auth/status       - Check auth status
  ├── /api/auth/refresh      - Refresh session
  ├── /api/auth/keep-alive   - Keep session alive
  ├── /api/auth/session-info - Get session info
  
  📊 PRODUCT ENDPOINTS:
  ├── /api/products          - All products
  ├── /api/products/search   - Search products
  ├── /api/products/:id      - Single product
  
  👤 USER ENDPOINTS:
  ├── /api/users/:id         - Get user profile
  ├── /api/user/inquiries    - User inquiries
  
  🐛 DEBUG ENDPOINTS:
  ├── /api/debug/session     - Session info
  ├── /api/debug/cookies     - Cookie info
  ├── /api/debug/db          - Database info
  
  💪 HEALTH CHECK:
  └── /api/health            - Server health
  
  ⚠️  IMPORTANT:
  ├── Set SESSION_SECRET in production
  ├── Set MONGODB_URI for session store
  ├── Use HTTPS in production
  └── Enable CORS for your frontend domains
  
  ✅ Server is ready with persistent sessions!
  ✅ Users will stay logged in for 30 days!
  ✅ Sessions survive browser restarts!
  ✅ Cross-tab session sync enabled!`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Server shutting down gracefully...');
  const { closeDB } = require('./database');
  await closeDB();
  console.log('✅ Database connection closed');
  process.exit(0);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
