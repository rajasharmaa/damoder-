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

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for production (Render/Heroku)
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// Enhanced CORS configuration for cross-origin
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin && process.env.NODE_ENV === 'development') {
      return callback(null, true);
    }
    
    const allowedOrigins = [
      'http://localhost:3000', 
      'http://127.0.0.1:5500', 
      'http://localhost:3001',
      'http://localhost:8080',
      'http://localhost:5173',
      'http://localhost:5174',
      'https://damoder-traders-x2iy.vercel.app',
      'https://damodertraders.onrender.com',
      'https://*.vercel.app'
    ];
    
    // Allow all vercel subdomains
    if (origin && (allowedOrigins.indexOf(origin) !== -1 || 
        origin.endsWith('.vercel.app') || 
        origin.includes('localhost'))) {
      callback(null, true);
    } else {
      console.log('⚠️  Blocked CORS for origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'Accept', 
    'Origin', 
    'X-Requested-With', 
    'X-CSRF-Token',
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

// Handle preflight requests explicitly
app.options('*', cors());

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Session configuration optimized for cross-origin
const isProduction = process.env.NODE_ENV === 'production';
const sessionConfig = {
  secret: process.env.SESSION_SECRET || 'damodar-traders-secret-key-2024',
  resave: false, // Don't save session if unmodified
  saveUninitialized: false, // Don't create session until something stored
  proxy: isProduction, // Trust reverse proxy in production
  name: 'dt_session_id', // Custom session cookie name
  cookie: { 
    secure: isProduction, // HTTPS only in production
    httpOnly: true, // Prevent client-side JS access
    sameSite: isProduction ? 'none' : 'lax', // Required for cross-origin
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    // Don't set domain for cross-origin compatibility
    path: '/',
    // Additional security for production
    ...(isProduction && { 
      domain: '.damodertraders.onrender.com', // Allow subdomains
    })
  },
  // Optional: Add session store for production (Redis recommended)
  // store: sessionStore
};

// Log session config for debugging
console.log('Session Configuration:', {
  isProduction,
  cookieSecure: sessionConfig.cookie.secure,
  cookieSameSite: sessionConfig.cookie.sameSite,
  cookieDomain: sessionConfig.cookie.domain
});

app.use(session(sessionConfig));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Helper function to validate ObjectId
function isValidObjectId(id) {
  if (!id) return false;
  return /^[0-9a-fA-F]{24}$/.test(id);
}

// User auth middleware
function requireUserAuth(req, res, next) {
  console.log('Auth check - Session user:', req.session.user);
  console.log('Auth check - Session ID:', req.sessionID);
  console.log('Auth check - Cookies:', req.cookies);
  
  if (!req.session.user) {
    console.log('❌ User not authenticated');
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.status(401).json({ 
        authenticated: false,
        error: 'Unauthorized - Please login first' 
      });
    }
    return res.status(401).json({ 
      authenticated: false,
      error: 'Please login first' 
    });
  }
  console.log('✅ User authenticated:', req.session.user.email);
  next();
}

// ==================== USER AUTHENTICATION ====================
app.get('/api/auth/status', (req, res) => {
  console.log('=== Auth Status Check ===');
  console.log('Session ID:', req.sessionID);
  console.log('Session user:', req.session.user);
  console.log('Origin:', req.headers.origin);
  console.log('Cookies received:', req.headers.cookie);
  
  if (req.session.user) {
    console.log('✅ Returning authenticated user');
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
    console.log('❌ No user in session');
    res.json({ 
      authenticated: false,
      message: 'Not authenticated'
    });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    
    console.log('Registration attempt:', { name, email });
    
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
    
    // Save session explicitly
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({ error: 'Failed to create session' });
      }
      
      console.log('✅ Registration successful for:', newUser.email);
      console.log('Session after registration:', req.session);
      
      res.status(201).json({ 
        message: 'Registration successful',
        user: {
          id: result.insertedId,
          name: newUser.name,
          email: newUser.email
        }
      });
    });
    
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('=== LOGIN ATTEMPT ===');
    console.log('Request body:', { email: req.body.email, password: '***' });
    console.log('Session ID:', req.sessionID);
    console.log('Origin:', req.headers.origin);
    console.log('Cookies received:', req.headers.cookie);
    
    const { email, password } = req.body;
    
    if (!email || !password) {
      console.log('Missing email or password');
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    // Find user
    const user = await usersCollection.findOne({ email });
    console.log('Found user:', user ? 'Yes' : 'No');
    
    if (!user) {
      console.log('User not found for email:', email);
      return res.status(401).json({ error: 'User not found. Please register first.' });
    }
    
    // Check password
    const passwordMatch = await bcrypt.compare(password, user.password);
    console.log('Password match:', passwordMatch);
    
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid password. Please try again.' });
    }
    
    // Create session
    req.session.user = {
      id: user._id.toString(),
      email: user.email,
      name: user.name,
      role: user.role
    };
    
    // Save session
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({ error: 'Failed to create session' });
      }
      
      console.log('✅ Login successful for user:', user.email);
      console.log('Session after login:', req.session);
      console.log('Session cookie details:', req.session.cookie);
      
      // Set additional cookie for debugging
      res.cookie('dt_logged_in', 'true', {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: false, // Allow JS access for debugging
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        path: '/'
      });
      
      res.json({ 
        message: 'Login successful',
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          phone: user.phone
        },
        session: {
          id: req.sessionID,
          cookie: req.session.cookie
        }
      });
    });
    
  } catch (err) {
    console.error('Login error:', err);
    console.error('Error stack:', err.stack);
    res.status(500).json({ 
      error: 'Login failed. Please try again.',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

app.post('/api/auth/logout', (req, res) => {
  console.log('=== LOGOUT ===');
  console.log('Session before logout:', req.session.user);
  
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    
    // Clear the session cookie
    res.clearCookie('dt_session_id', {
      path: '/',
      domain: process.env.NODE_ENV === 'production' ? '.damodertraders.onrender.com' : undefined
    });
    
    // Clear debug cookie
    res.clearCookie('dt_logged_in', {
      path: '/',
      domain: process.env.NODE_ENV === 'production' ? '.damodertraders.onrender.com' : undefined
    });
    
    console.log('✅ Logout successful');
    res.json({ 
      message: 'Logout successful',
      timestamp: new Date().toISOString()
    });
  });
});

// ==================== FORGOT PASSWORD ROUTES ====================

// Check if email exists
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
      message: user ? 'Account exists' : 'No account found',
      user: user ? {
        id: user._id,
        name: user.name,
        email: user.email,
        hasAccount: true
      } : null
    });
  } catch (err) {
    console.error('Error checking email:', err);
    res.status(500).json({ 
      exists: false,
      message: 'Error checking email',
      error: err.message 
    });
  }
});

// Forgot password request
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    // Check if user exists
    const user = await usersCollection.findOne({ email });
    
    if (!user) {
      // Return success even if user doesn't exist (security best practice)
      return res.json({ 
        message: 'If an account exists with this email, you will receive password reset instructions.',
        sent: true 
      });
    }
    
    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now
    
    // Save reset token to user document
    await usersCollection.updateOne(
      { _id: user._id },
      { 
        $set: { 
          resetToken,
          resetTokenExpiry: new Date(resetTokenExpiry)
        } 
      }
    );
    
    // In production, send email with reset link
    const resetLink = `${process.env.FRONTEND_URL || 'https://damoder-traders-x2iy.vercel.app'}/reset-password?token=${resetToken}`;
    
    console.log('Password reset link:', resetLink); // For development only
    
    // TODO: Implement actual email sending
    // sendResetEmail(user.email, resetLink);
    
    res.json({ 
      message: 'Password reset instructions sent to your email.',
      sent: true,
      // For development only - remove in production
      development: { resetLink }
    });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Failed to process password reset request' });
  }
});

// Reset password with token
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
    
    // Find user with valid reset token
    const user = await usersCollection.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: new Date() }
    });
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Update password and clear reset token
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
      message: 'Password reset successful. You can now login with your new password.',
      success: true 
    });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Password strength validation
app.post('/api/auth/validate-password', (req, res) => {
  const { password } = req.body;
  
  const validations = {
    length: password.length >= 6,
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasNumber: /\d/.test(password),
    hasSpecial: /[!@#$%^&*(),.?":{}|<>]/.test(password)
  };
  
  const isValid = Object.values(validations).every(v => v);
  
  res.json({
    valid: isValid,
    validations,
    score: Object.values(validations).filter(v => v).length
  });
});

// ==================== ENHANCED PRODUCT ROUTES WITH SEARCH ====================

// Get all products
app.get('/api/products', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const products = await productsCollection.find().sort({ createdAt: -1 }).toArray();
    res.json(products);
  } catch (err) {
    console.error('Error fetching products:', err);
    res.json([]); // Return empty array instead of error
  }
});

// Get products by category
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
    res.json([]); // Return empty array instead of error
  }
});

// Search products
app.get('/api/products/search', async (req, res) => {
  try {
    const { search, category } = req.query;
    
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    
    // Build query
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
    res.json([]); // Return empty array instead of error
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
    res.json([]); // Return empty array instead of error
  }
});

// Get single product by ID
app.get('/api/products/:id', async (req, res) => {
  try {
    // Validate ObjectId format
    if (!isValidObjectId(req.params.id)) {
      console.warn(`Invalid product ID format: ${req.params.id}`);
      return res.json(null); // Return null instead of error
    }
    
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const product = await productsCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    
    if (!product) {
      return res.json(null); // Return null instead of 404 error
    }
    res.json(product);
  } catch (err) {
    console.error('Error fetching product:', err);
    
    // Handle specific ObjectId errors
    if (err.message.includes('must be a 24 character hex string') || 
        err.message.includes('Argument passed in must be a string of 12 bytes')) {
      return res.json(null); // Return null for invalid IDs
    }
    
    // For other errors, return null
    res.json(null);
  }
});

// Get products with discount
app.get('/api/products/discounted', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    
    // Use $exists to ensure discount field exists and is greater than 0
    const discountedProducts = await productsCollection.find({ 
      discount: { $exists: true, $ne: null, $gt: 0 } 
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

// ==================== USER INQUIRIES ROUTES ====================

app.get('/api/user/inquiries', requireUserAuth, async (req, res) => {
  try {
    // Debug: Log session information
    console.log('=== DEBUG: User Inquiries Request ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session user:', req.session.user);
    
    // Validate that session user ID is valid
    if (!req.session.user?.id) {
      console.warn('No user ID in session');
      return res.json([]);
    }
    
    // Convert to string if it's an ObjectId
    const userId = req.session.user.id.toString();
    console.log('User ID from session:', userId);
    
    if (!isValidObjectId(userId)) {
      console.warn(`Invalid user session ID format: ${userId}`);
      return res.json([]);
    }
    
    const db = await connectToDB();
    const inquiriesCollection = db.collection('inquiries');
    
    console.log('Looking for inquiries with user ID:', userId);
    
    // Try to find inquiries with this userId
    const inquiries = await inquiriesCollection.find({ 
      userId: new ObjectId(userId) 
    }).sort({ createdAt: -1 }).toArray();
    
    console.log(`Found ${inquiries.length} inquiries for user ${userId}`);
    
    // If no inquiries found with userId, try with email (backward compatibility)
    if (inquiries.length === 0) {
      console.log('No inquiries found with userId, trying with email:', req.session.user.email);
      
      const inquiriesByEmail = await inquiriesCollection.find({ 
        email: req.session.user.email 
      }).sort({ createdAt: -1 }).toArray();
      
      console.log(`Found ${inquiriesByEmail.length} inquiries by email`);
      
      // Update these inquiries with the userId for future reference
      if (inquiriesByEmail.length > 0) {
        await inquiriesCollection.updateMany(
          { email: req.session.user.email, userId: { $exists: false } },
          { $set: { userId: new ObjectId(userId) } }
        );
      }
      
      return res.json(inquiriesByEmail);
    }
    
    res.json(inquiries);
  } catch (err) {
    console.error('Error fetching user inquiries:', err);
    console.error('Error stack:', err.stack);
    
    // Handle specific ObjectId errors gracefully
    if (err.message.includes('must be a 24 character hex string') || 
        err.message.includes('Argument passed in must be a string of 12 bytes')) {
      console.warn('ObjectId parsing error');
      return res.json([]);
    }
    
    res.json([]);
  }
});

// ==================== USER PROFILE ROUTES ====================

app.get('/api/users/:id', requireUserAuth, async (req, res) => {
  try {
    // Validate ObjectId format
    if (!isValidObjectId(req.params.id)) {
      console.warn(`Invalid user ID format: ${req.params.id}`);
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
    
    // Check if requesting user owns this profile
    if (req.session.user.id.toString() !== req.params.id && req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    res.json(user);
  } catch (err) {
    console.error('Error fetching user:', err);
    
    // Handle specific ObjectId errors
    if (err.message.includes('must be a 24 character hex string') || 
        err.message.includes('Argument passed in must be a string of 12 bytes')) {
      return res.json(null);
    }
    
    res.json(null);
  }
});

app.put('/api/users/:id', requireUserAuth, async (req, res) => {
  try {
    // Validate ObjectId format
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
    
    // Allow password update if provided
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
    
    const updatedUser = await usersCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    }, { projection: { password: 0 } });
    
    res.json(updatedUser);
  } catch (err) {
    console.error('Error updating user:', err);
    
    // Handle specific ObjectId errors
    if (err.message.includes('must be a 24 character hex string') || 
        err.message.includes('Argument passed in must be a string of 12 bytes')) {
      return res.status(400).json({ error: 'Invalid user ID format' });
    }
    
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// ==================== DEBUG & TEST ENDPOINTS ====================

app.get('/api/debug/session', (req, res) => {
  res.json({
    sessionId: req.sessionID,
    session: req.session,
    user: req.session.user,
    cookies: req.cookies,
    headers: {
      origin: req.headers.origin,
      cookie: req.headers.cookie,
      'user-agent': req.headers['user-agent']
    },
    timestamp: new Date().toISOString()
  });
});

app.get('/api/debug/cookies', (req, res) => {
  res.json({
    cookies: req.cookies,
    sessionId: req.sessionID,
    session: req.session,
    headers: {
      origin: req.headers.origin,
      cookie: req.headers.cookie,
      'user-agent': req.headers['user-agent']
    }
  });
});

app.get('/api/debug/db', async (req, res) => {
  try {
    const db = await connectToDB();
    const collections = await db.listCollections().toArray();
    
    res.json({
      success: true,
      collections: collections.map(c => c.name),
      message: 'Database connection successful'
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message,
      message: 'Database connection failed'
    });
  }
});

app.get('/api/test/inquiries', async (req, res) => {
  try {
    const db = await connectToDB();
    const inquiriesCollection = db.collection('inquiries');
    
    // Get a sample of inquiries
    const sampleInquiries = await inquiriesCollection.find().limit(5).toArray();
    
    res.json({
      success: true,
      totalCount: await inquiriesCollection.countDocuments(),
      sampleCount: sampleInquiries.length,
      sample: sampleInquiries,
      message: 'Database connection test successful'
    });
  } catch (err) {
    console.error('Test endpoint error:', err);
    res.status(500).json({
      success: false,
      error: err.message,
      message: 'Database connection failed'
    });
  }
});

// Test endpoint for CORS and connectivity
app.get('/api/test', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    cors: {
      origin: req.headers.origin,
      allowed: true
    },
    session: {
      id: req.sessionID,
      hasUser: !!req.session.user
    },
    cookies: req.cookies,
    message: 'API is working correctly'
  });
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'Damodar Traders Main Website API',
    version: '2.0.0',
    cors: {
      origin: req.headers.origin,
      allowed: true
    },
    session: {
      id: req.sessionID,
      hasUser: !!req.session.user
    },
    features: [
      'product-search',
      'search-suggestions',
      'category-filtering',
      'user-authentication',
      'inquiry-management',
      'user-inquiries',
      'forgot-password',
      'password-reset'
    ]
  });
});

// ==================== SERVER STARTUP ====================

app.listen(PORT, async () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║           DAMODAR TRADERS SERVER STARTING               ║
╚══════════════════════════════════════════════════════════╝
  
  🚀 Server running on port: ${PORT}
  📁 Static files from: ${path.join(__dirname, 'public')}
  🔧 API Base URL: http://localhost:${PORT}/api
  🌍 Environment: ${process.env.NODE_ENV || 'development'}
  
  🔍 Search Endpoints:
  ├── /api/products/search            - Search products
  ├── /api/products/search/suggestions - Real-time suggestions
  ├── /api/products/discounted        - Discounted products
  ├── /api/products/popular           - Popular products
  
  🔐 Auth Endpoints:
  ├── /api/auth/register              - User registration
  ├── /api/auth/login                 - User login
  ├── /api/auth/logout                - User logout
  ├── /api/auth/status                - Auth status
  ├── /api/auth/forgot-password       - Forgot password
  ├── /api/auth/reset-password        - Reset password
  ├── /api/auth/check-email           - Check email exists
  
  📊 Product Endpoints:
  ├── /api/products                   - All products
  ├── /api/products/category/:category - Products by category
  ├── /api/products/:id               - Single product
  
  📝 Inquiry Endpoints:
  ├── /api/inquiries                  - Submit inquiry
  ├── /api/user/inquiries             - User inquiries
  
  👤 User Endpoints:
  ├── /api/users/:id                  - Get user profile
  ├── /api/users/:id                  - Update user profile
  
  🐛 Debug Endpoints:
  ├── /api/debug/session              - Session info
  ├── /api/debug/cookies              - Cookie info
  ├── /api/debug/db                   - Database info
  ├── /api/test/inquiries             - Test inquiries
  ├── /api/test                       - Test endpoint
  
  💪 Health Check:
  └── /api/health                     - Server health
  
  👤 User login: http://localhost:${PORT}/login
  🔐 Reset password: http://localhost:${PORT}/reset-password
  🏪 Products page: http://localhost:${PORT}/categories.html
  👤 Account page: http://localhost:${PORT}/account
  
  ⚠️  Important: For production, set SESSION_SECRET and MONGODB_URI environment variables
  
  ✅ Server is ready!`);
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
