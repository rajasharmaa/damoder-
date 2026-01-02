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

// Try different import methods for connect-mongo
let MongoStore;
try {
  // For newer versions
  MongoStore = require('connect-mongo').default || require('connect-mongo');
} catch (err) {
  console.log('connect-mongo not found, using memory store');
  MongoStore = null;
}

const app = express();
const PORT = process.env.PORT || 3000;

// CORS configuration - ALLOW ALL FOR DEVELOPMENT
const corsOptions = {
  origin: function (origin, callback) {
    // Allow all origins for development
    if (process.env.NODE_ENV === 'development' || !process.env.NODE_ENV) {
      return callback(null, true);
    }
    
    // Production: allow specific origins
    const allowedOrigins = [
      'http://localhost:3000', 
      'http://127.0.0.1:5500', 
      'http://localhost:3001',
      'http://localhost:8080',
      'http://192.168.1.9:8080',
      'http://192.168.1.9:3000',
      'https://damodertraders.onrender.com'
    ];
    
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Auth-Token'],
  credentials: true,
  exposedHeaders: ['Set-Cookie']
};

app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Enhanced session configuration
const sessionConfig = {
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: '/',
  },
  name: 'damodar_auth',
  proxy: true // Trust proxy for secure cookies
};

// Add MongoStore if available
if (MongoStore && process.env.MONGODB_URI) {
  try {
    sessionConfig.store = new MongoStore({
      mongoUrl: process.env.MONGODB_URI,
      ttl: 24 * 60 * 60, // 1 day
      autoRemove: 'native'
    });
    console.log('Using MongoDB session store');
  } catch (err) {
    console.log('Failed to create MongoStore, using memory store:', err.message);
  }
} else {
  console.log('Using memory session store (not recommended for production)');
}

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
  console.log('=== Auth Middleware Check ===');
  console.log('Session ID:', req.sessionID);
  console.log('Session user:', req.session.user);
  console.log('Headers:', req.headers);
  
  // Check session first
  if (req.session.user) {
    console.log('User authenticated via session');
    return next();
  }
  
  // Check for token in headers
  const token = req.headers['x-auth-token'];
  if (token) {
    console.log('Token found in headers');
    // Validate token (simplified - in production use JWT)
    try {
      const tokenData = JSON.parse(Buffer.from(token, 'base64').toString());
      if (tokenData.userId && tokenData.expiry > Date.now()) {
        req.session.user = {
          id: tokenData.userId,
          email: tokenData.email,
          name: tokenData.name,
          role: tokenData.role || 'user'
        };
        console.log('User authenticated via token');
        return next();
      }
    } catch (err) {
      console.log('Token validation failed:', err.message);
    }
  }
  
  console.log('No valid authentication found');
  return res.status(401).json({ 
    error: 'Unauthorized', 
    message: 'Please login to access this resource',
    requiresLogin: true 
  });
}

// ==================== ENHANCED AUTH ENDPOINTS ====================

app.get('/api/auth/status', (req, res) => {
  console.log('=== Auth Status Check ===');
  console.log('Request Origin:', req.headers.origin);
  console.log('Session ID:', req.sessionID);
  console.log('Session:', req.session);
  console.log('Cookies:', req.cookies);
  
  if (req.session.user) {
    // Generate a token for cross-origin requests
    const tokenData = {
      userId: req.session.user.id,
      email: req.session.user.email,
      name: req.session.user.name,
      role: req.session.user.role,
      expiry: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
    };
    
    const authToken = Buffer.from(JSON.stringify(tokenData)).toString('base64');
    
    res.json({ 
      authenticated: true, 
      user: {
        id: req.session.user.id,
        name: req.session.user.name,
        email: req.session.user.email,
        role: req.session.user.role
      },
      token: authToken
    });
  } else {
    console.log('No user in session');
    res.json({ 
      authenticated: false,
      message: 'Not logged in'
    });
  }
});

// Enhanced registration with token generation
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    
    console.log('Registration attempt:', { name, email, phone });
    
    if (!name || !email || !password) {
      return res.status(400).json({ 
        error: 'Validation failed',
        message: 'Name, email and password are required' 
      });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    // Check if user already exists
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        error: 'User exists',
        message: 'User with this email already exists. Please login.' 
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
      createdAt: new Date(),
      updatedAt: new Date(),
      lastLogin: new Date()
    };
    
    const result = await usersCollection.insertOne(newUser);
    
    const userId = result.insertedId.toString();
    
    // Create session
    req.session.user = {
      id: userId,
      email: newUser.email,
      name: newUser.name,
      role: 'user'
    };
    
    // Generate token
    const tokenData = {
      userId: userId,
      email: newUser.email,
      name: newUser.name,
      role: 'user',
      expiry: Date.now() + (24 * 60 * 60 * 1000)
    };
    
    const authToken = Buffer.from(JSON.stringify(tokenData)).toString('base64');
    
    // Update last login
    await usersCollection.updateOne(
      { _id: result.insertedId },
      { $set: { lastLogin: new Date() } }
    );
    
    console.log('Registration successful for:', email);
    
    res.status(201).json({ 
      success: true,
      message: 'Registration successful',
      user: {
        id: userId,
        name: newUser.name,
        email: newUser.email,
        phone: newUser.phone
      },
      token: authToken
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ 
      error: 'Registration failed',
      message: 'An error occurred during registration. Please try again.' 
    });
  }
});

// Enhanced login with multiple auth methods
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    console.log('Login attempt for:', email);
    
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Validation failed',
        message: 'Email and password are required' 
      });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    // Find user
    const user = await usersCollection.findOne({ email });
    if (!user) {
      console.log('User not found:', email);
      return res.status(401).json({ 
        error: 'Authentication failed',
        message: 'Invalid email or password. Please try again.',
        code: 'USER_NOT_FOUND'
      });
    }
    
    // Check password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      console.log('Invalid password for:', email);
      return res.status(401).json({ 
        error: 'Authentication failed',
        message: 'Invalid email or password. Please try again.',
        code: 'INVALID_PASSWORD'
      });
    }
    
    const userId = user._id.toString();
    
    // Create session
    req.session.user = {
      id: userId,
      email: user.email,
      name: user.name,
      role: user.role
    };
    
    // Generate token for cross-origin
    const tokenData = {
      userId: userId,
      email: user.email,
      name: user.name,
      role: user.role,
      expiry: Date.now() + (24 * 60 * 60 * 1000)
    };
    
    const authToken = Buffer.from(JSON.stringify(tokenData)).toString('base64');
    
    // Update last login
    await usersCollection.updateOne(
      { _id: user._id },
      { $set: { lastLogin: new Date() } }
    );
    
    // Save session explicitly
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
      } else {
        console.log('Session saved for:', email);
      }
    });
    
    console.log('Login successful for:', email);
    console.log('Session ID:', req.sessionID);
    
    res.json({ 
      success: true,
      message: 'Login successful',
      user: {
        id: userId,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role
      },
      token: authToken,
      sessionId: req.sessionID
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ 
      error: 'Login failed',
      message: 'An error occurred during login. Please try again.' 
    });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const userEmail = req.session.user?.email;
  
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ 
        error: 'Logout failed',
        message: 'Failed to logout. Please try again.' 
      });
    }
    
    // Clear the session cookie
    res.clearCookie('damodar_auth', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      path: '/'
    });
    
    console.log('Logout successful for:', userEmail);
    res.json({ 
      success: true,
      message: 'Logout successful' 
    });
  });
});

// Token refresh endpoint
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ 
        error: 'Token required',
        message: 'Authentication token is required' 
      });
    }
    
    // Decode and validate token
    const tokenData = JSON.parse(Buffer.from(token, 'base64').toString());
    
    if (tokenData.expiry < Date.now()) {
      return res.status(401).json({ 
        error: 'Token expired',
        message: 'Your session has expired. Please login again.' 
      });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const user = await usersCollection.findOne({ 
      _id: new ObjectId(tokenData.userId) 
    });
    
    if (!user) {
      return res.status(401).json({ 
        error: 'User not found',
        message: 'User account not found. Please register.' 
      });
    }
    
    // Create new token with extended expiry
    const newTokenData = {
      userId: tokenData.userId,
      email: user.email,
      name: user.name,
      role: user.role,
      expiry: Date.now() + (24 * 60 * 60 * 1000)
    };
    
    const newToken = Buffer.from(JSON.stringify(newTokenData)).toString('base64');
    
    // Also create/update session
    req.session.user = {
      id: tokenData.userId,
      email: user.email,
      name: user.name,
      role: user.role
    };
    
    res.json({
      success: true,
      token: newToken,
      user: {
        id: tokenData.userId,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
    
  } catch (err) {
    console.error('Token refresh error:', err);
    res.status(401).json({ 
      error: 'Invalid token',
      message: 'Invalid authentication token' 
    });
  }
});

// ==================== FORGOT PASSWORD ROUTES ====================

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
    const resetLink = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
    
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

// Get single product by ID - FIXED VERSION
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

// Get products with discount - FIXED VERSION
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
    // Return empty array instead of error for better UX
    res.json([]);
  }
});

// Get popular products - FIXED VERSION
app.get('/api/products/popular', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    
    // For now, return products with highest discount
    // You can modify this to use actual popularity metrics
    const popularProducts = await productsCollection.find({ 
      discount: { $exists: true, $ne: null, $gt: 0 } 
    }).sort({ discount: -1 }).limit(10).toArray();
    
    res.json(popularProducts || []);
  } catch (err) {
    console.error('Error fetching popular products:', err);
    // Return empty array instead of error for better UX
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
    
    // Return empty array for any other errors
    res.json([]);
  }
});

// ==================== USER PROFILE ROUTES ====================

app.get('/api/users/:id', requireUserAuth, async (req, res) => {
  try {
    // Validate ObjectId format
    if (!isValidObjectId(req.params.id)) {
      console.warn(`Invalid user ID format: ${req.params.id}`);
      return res.json(null); // Return null instead of error
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const user = await usersCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    }, { projection: { password: 0 } });
    
    if (!user) {
      return res.json(null); // Return null instead of 404
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
    
    res.json(null); // Return null for any errors
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

// ==================== DEBUG ENDPOINTS ====================

app.get('/api/debug/session', (req, res) => {
  res.json({
    sessionId: req.sessionID,
    session: req.session,
    user: req.session.user,
    cookies: req.cookies,
    timestamp: new Date().toISOString()
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

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'Damodar Traders Main Website API',
    version: '2.0.0',
    features: [
      'product-search',
      'search-suggestions',
      'category-filtering',
      'user-authentication',
      'inquiry-management',
      'user-inquiries',
      'forgot-password',
      'password-reset',
      'token-auth',
      'session-auth'
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
  🌐 Environment: ${process.env.NODE_ENV || 'development'}
  🔧 API Base URL: https://damodertraders.onrender.com/api
  
  🔐 AUTHENTICATION METHODS:
  ├── Session-based (cookies) for same-origin
  ├── Token-based for cross-origin
  ├── Dual authentication support
  
  📱 SUPPORTED ORIGINS:
  ├── http://localhost:3000
  ├── http://localhost:8080
  ├── http://192.168.1.9:8080
  ├── http://192.168.1.9:3000
  └── https://damodertraders.onrender.com
  
  ✅ Server is ready!`);
  
  // Test database connection
  try {
    const db = await connectToDB();
    console.log('✅ Database connected successfully');
  } catch (err) {
    console.error('❌ Database connection failed:', err.message);
  }
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
