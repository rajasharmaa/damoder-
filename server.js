require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const { connectToDB } = require('./database');
const { ObjectId } = require('mongodb');
const crypto = require('crypto');
const MongoStore = require('connect-mongo');

const app = express();
const PORT = process.env.PORT || 3000;

// Determine environment
const isProduction = process.env.NODE_ENV === 'production';

// Allowed origins - ADD ALL YOUR DOMAINS HERE
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:8080',
  'http://127.0.0.1:5500',
  'http://127.0.0.1:8080',
  'http://localhost:5173',
  'https://damoder-traders-x2iy.vercel.app',  // Your Vercel frontend
  'https://damodartraders.vercel.app',       // Other possible Vercel URLs
  'https://damodartraders.com',              // Your main domain
  'https://www.damodartraders.com',          // WWW version
  process.env.FRONTEND_URL || 'https://damoder-traders-x2iy.vercel.app'
].filter(Boolean);

console.log('🌍 Allowed Origins for CORS:', allowedOrigins);

// ==================== MIDDLEWARE SETUP ====================

// 1. CORS Middleware - HANDLE FIRST
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // Check if origin is in allowed list
  if (origin && allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD');
  res.header('Access-Control-Allow-Headers', 
    'Content-Type, Authorization, X-Requested-With, Accept, Origin, Cache-Control, Pragma, If-Modified-Since'
  );
  res.header('Access-Control-Expose-Headers', 'set-cookie');
  res.header('Access-Control-Max-Age', '86400');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  
  next();
});

// 2. Body parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// 3. Session configuration
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGODB_URI || "mongodb+srv://rajat888sharma111_db_user:rajat888@cluster0.c6jicll.mongodb.net/damodarTraders?retryWrites=true&w=majority",
  collectionName: 'sessions',
  ttl: 24 * 60 * 60, // 24 hours
  autoRemove: 'native',
  crypto: {
    secret: process.env.SESSION_SECRET || 'your-session-secret'
  }
});

app.use(session({
  secret: process.env.SESSION_SECRET || 'damodar-traders-session-secret-2024',
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  cookie: { 
    secure: isProduction, // true for HTTPS
    httpOnly: true,
    sameSite: isProduction ? 'none' : 'lax', // 'none' for cross-site
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    domain: isProduction ? '.onrender.com' : undefined
  },
  name: 'damodar.sid',
  proxy: true // Trust reverse proxy
}));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// ==================== HELPER FUNCTIONS ====================

function isValidObjectId(id) {
  if (!id) return false;
  return /^[0-9a-fA-F]{24}$/.test(id);
}

function requireUserAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ 
      authenticated: false,
      error: 'Please login first' 
    });
  }
  next();
}

// ==================== AUTHENTICATION ROUTES ====================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'Damodar Traders API',
    cors: 'enabled',
    allowedOrigins: allowedOrigins
  });
});

// Auth status - NO CACHE HEADERS
app.get('/api/auth/status', (req, res) => {
  // Explicitly set CORS headers for this endpoint
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  res.header('Access-Control-Allow-Credentials', 'true');
  
  // Do NOT set cache-control headers here
  console.log('🔐 Auth status check from:', origin);
  
  if (req.session.user) {
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
    res.json({ 
      authenticated: false,
      user: null 
    });
  }
});

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email and password are required' });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    // Check if user already exists
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = {
      name,
      email,
      phone: phone || '',
      password: hashedPassword,
      role: 'user',
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    const result = await usersCollection.insertOne(newUser);
    
    // Create session
    req.session.user = {
      id: result.insertedId.toString(),
      email: newUser.email,
      name: newUser.name,
      role: 'user'
    };
    
    // CORS headers
    const origin = req.headers.origin;
    if (origin && allowedOrigins.includes(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
    }
    res.header('Access-Control-Allow-Credentials', 'true');
    
    res.status(201).json({ 
      message: 'Registration successful',
      authenticated: true,
      user: {
        id: result.insertedId.toString(),
        name: newUser.name,
        email: newUser.email
      }
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login - SIMPLIFIED
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'User not found. Please register first.' });
    }
    
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid password. Please try again.' });
    }
    
    // Set session
    req.session.user = {
      id: user._id.toString(),
      email: user.email,
      name: user.name,
      role: user.role || 'user'
    };
    
    // Save session
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({ error: 'Session creation failed' });
      }
      
      // CORS headers
      const origin = req.headers.origin;
      if (origin && allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
      }
      res.header('Access-Control-Allow-Credentials', 'true');
      
      res.json({ 
        message: 'Login successful',
        authenticated: true,
        user: {
          id: user._id.toString(),
          name: user.name,
          email: user.email,
          phone: user.phone,
          role: user.role || 'user'
        }
      });
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  // CORS headers
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  res.header('Access-Control-Allow-Credentials', 'true');
  
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    
    res.clearCookie('damodar.sid', {
      path: '/',
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax'
    });
    
    res.json({ 
      message: 'Logout successful',
      authenticated: false 
    });
  });
});

// Check email
app.get('/api/auth/check-email', async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ 
        exists: false,
        message: 'Email is required' 
      });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const user = await usersCollection.findOne({ email });
    
    res.json({ 
      exists: !!user,
      message: user ? 'Account exists' : 'No account found'
    });
  } catch (err) {
    console.error('Error checking email:', err);
    res.status(500).json({ 
      exists: false,
      message: 'Error checking email'
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
      // Security: don't reveal if user exists
      return res.json({ 
        message: 'If an account exists with this email, you will receive password reset instructions.',
        sent: true 
      });
    }
    
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour
    
    await usersCollection.updateOne(
      { _id: user._id },
      { 
        $set: { 
          resetToken,
          resetTokenExpiry: new Date(resetTokenExpiry)
        } 
      }
    );
    
    const resetLink = `https://damoder-traders-x2iy.vercel.app/reset-password?token=${resetToken}`;
    
    console.log('Password reset link:', resetLink); // Remove in production
    
    res.json({ 
      message: 'Password reset instructions sent to your email.',
      sent: true,
      development: { resetLink } // Remove in production
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
      resetTokenExpiry: { $gt: new Date() }
    });
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    await usersCollection.updateOne(
      { _id: user._id },
      { 
        $set: { 
          password: hashedPassword,
          updatedAt: new Date()
        },
        $unset: {
          resetToken: "",
          resetTokenExpiry: ""
        }
      }
    );
    
    res.json({ 
      message: 'Password reset successful.',
      success: true 
    });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ==================== PRODUCT ROUTES ====================

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

app.get('/api/products/category/:category', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const products = await productsCollection.find({ 
      category: req.params.category 
    }).sort({ createdAt: -1 }).toArray();
    res.json(products);
  } catch (err) {
    console.error('Error fetching products by category:', err);
    res.json([]);
  }
});

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
        { material: { $regex: search, $options: 'i' } }
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
            { material: { $regex: query, $options: 'i' } }
          ]
        }
      },
      {
        $project: {
          name: 1,
          category: 1,
          _id: 1,
          score: {
            $add: [
              { $cond: [ 
                { $regexMatch: { input: "$name", regex: new RegExp(query, "i") } }, 
                10, 
                0 
              ]},
              { $cond: [ 
                { $regexMatch: { input: "$category", regex: new RegExp(query, "i") } }, 
                5, 
                0 
              ]},
              { $cond: [ 
                { $regexMatch: { input: "$material", regex: new RegExp(query, "i") } }, 
                3, 
                0 
              ]}
            ]
          }
        }
      },
      { $sort: { score: -1 } },
      { $limit: 10 }
    ]).toArray();

    res.json(suggestions);
  } catch (err) {
    console.error('Error fetching search suggestions:', err);
    res.json([]);
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    if (!isValidObjectId(req.params.id)) {
      console.warn(`Invalid product ID format: ${req.params.id}`);
      return res.json(null);
    }
    
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const product = await productsCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    
    if (!product) {
      return res.json(null);
    }
    res.json(product);
  } catch (err) {
    console.error('Error fetching product:', err);
    res.json(null);
  }
});

app.get('/api/products/discounted', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    
    const discountedProducts = await productsCollection.find({ 
      discount: { $exists: true, $ne: null, $gt: 0 } 
    }).sort({ discount: -1 }).limit(10).toArray();
    
    res.json(discountedProducts || []);
  } catch (err) {
    console.error('Error fetching discounted products:', err);
    res.json([]);
  }
});

app.get('/api/products/popular', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    
    const popularProducts = await productsCollection.find({ 
      discount: { $exists: true, $ne: null, $gt: 0 } 
    }).sort({ discount: -1 }).limit(10).toArray();
    
    res.json(popularProducts || []);
  } catch (err) {
    console.error('Error fetching popular products:', err);
    res.json([]);
  }
});

// ==================== INQUIRY ROUTES ====================

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
      userId: req.body.userId || null
    };
    
    const result = await inquiriesCollection.insertOne(newInquiry);
    res.status(201).json({ 
      ...newInquiry, 
      _id: result.insertedId, 
      message: 'Inquiry submitted successfully' 
    });
  } catch (err) {
    console.error('Error creating inquiry:', err);
    res.status(500).json({ error: 'Failed to submit inquiry' });
  }
});

app.get('/api/user/inquiries', requireUserAuth, async (req, res) => {
  try {
    if (!req.session.user?.id) {
      return res.json([]);
    }
    
    const userId = req.session.user.id.toString();
    
    if (!isValidObjectId(userId)) {
      return res.json([]);
    }
    
    const db = await connectToDB();
    const inquiriesCollection = db.collection('inquiries');
    
    const inquiries = await inquiriesCollection.find({ 
      userId: new ObjectId(userId) 
    }).sort({ createdAt: -1 }).toArray();
    
    if (inquiries.length === 0) {
      const inquiriesByEmail = await inquiriesCollection.find({ 
        email: req.session.user.email 
      }).sort({ createdAt: -1 }).toArray();
      
      return res.json(inquiriesByEmail);
    }
    
    res.json(inquiries);
  } catch (err) {
    console.error('Error fetching user inquiries:', err);
    res.json([]);
  }
});

// ==================== USER ROUTES ====================

app.get('/api/users/:id', requireUserAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.id)) {
      return res.json(null);
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const user = await usersCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    }, { projection: { password: 0 } });
    
    if (!user) {
      return res.json(null);
    }
    
    if (req.session.user.id.toString() !== req.params.id && req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    res.json(user);
  } catch (err) {
    console.error('Error fetching user:', err);
    res.json(null);
  }
});

app.put('/api/users/:id', requireUserAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid user ID format' });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const updateData = {
      name: req.body.name,
      phone: req.body.phone,
      updatedAt: new Date()
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
    
    if (req.body.name && req.session.user) {
      req.session.user.name = req.body.name;
      req.session.save();
    }
    
    const updatedUser = await usersCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    }, { projection: { password: 0 } });
    
    res.json(updatedUser);
  } catch (err) {
    console.error('Error updating user:', err);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// ==================== DEBUG & TEST ROUTES ====================

app.get('/api/debug/cors-test', (req, res) => {
  const origin = req.headers.origin;
  const headers = req.headers;
  
  res.json({
    origin,
    headers: {
      'access-control-request-headers': headers['access-control-request-headers'],
      'access-control-request-method': headers['access-control-request-method']
    },
    allowedOrigins: allowedOrigins,
    isOriginAllowed: origin && allowedOrigins.includes(origin),
    timestamp: new Date().toISOString()
  });
});

app.get('/api/test/simple', (req, res) => {
  res.json({ 
    message: 'Simple test endpoint - no CORS issues',
    timestamp: new Date().toISOString() 
  });
});

// ==================== CATCH-ALL FOR OPTIONS ====================

// Handle all OPTIONS requests
app.options('*', (req, res) => {
  const origin = req.headers.origin;
  
  if (origin && allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD');
  res.header('Access-Control-Allow-Headers', 
    'Content-Type, Authorization, X-Requested-With, Accept, Origin, Cache-Control, Pragma, If-Modified-Since'
  );
  res.header('Access-Control-Max-Age', '86400');
  res.status(204).send();
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ==================== SERVER STARTUP ====================

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║           DAMODAR TRADERS SERVER v3.0                   ║
╚══════════════════════════════════════════════════════════╝
  
  🚀 Server: https://damodertraders.onrender.com
  📡 Port: ${PORT}
  🌍 Environment: ${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'}
  🔐 CORS: ENABLED
  
  ✅ Allowed Origins (${allowedOrigins.length}):
  ${allowedOrigins.map(o => `  • ${o}`).join('\n')}
  
  🔧 Test Endpoints:
  • GET  /api/health          - Health check
  • GET  /api/test/simple     - Simple CORS test
  • GET  /api/debug/cors-test - CORS debug
  
  👤 Auth Endpoints:
  • GET  /api/auth/status     - Check auth status
  • POST /api/auth/login      - Login
  • POST /api/auth/logout     - Logout
  • POST /api/auth/register   - Register
  
  🏪 Frontend: https://damoder-traders-x2iy.vercel.app
  
  ✅ Server is ready and CORS configured!`);
});
