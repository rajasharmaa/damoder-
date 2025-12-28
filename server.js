
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const { connectToDB } = require('./database');
const { ObjectId } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS configuration
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'http://localhost:3001'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'user123',
  resave: true,
  saveUninitialized: false,
  cookie: { 
    secure: false,
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// User auth middleware
function requireUserAuth(req, res, next) {
  if (!req.session.user) {
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    return res.status(401).json({ error: 'Please login first' });
  }
  next();
}

// ==================== USER AUTHENTICATION ====================

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
      id: result.insertedId,
      email: newUser.email,
      name: newUser.name,
      role: 'user'
    };
    
    res.status(201).json({ 
      message: 'Registration successful',
      user: {
        id: result.insertedId,
        name: newUser.name,
        email: newUser.email
      }
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    // Find user
    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Create session
    req.session.user = {
      id: user._id,
      email: user.email,
      name: user.name,
      role: user.role
    };
    
    res.json({ 
      message: 'Login successful',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Logout successful' });
  });
});

app.get('/api/auth/status', (req, res) => {
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
    res.json({ authenticated: false });
  }
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
    res.status(500).json({ error: 'Failed to fetch products' });
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
    res.status(500).json({ error: 'Failed to fetch products' });
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
    res.status(500).json({ error: 'Failed to search products' });
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
    res.status(500).json({ error: 'Failed to fetch suggestions' });
  }
});

// Get single product by ID
app.get('/api/products/:id', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    const product = await productsCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json(product);
  } catch (err) {
    console.error('Error fetching product:', err);
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});

// Get products with discount
app.get('/api/products/discounted', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    
    const discountedProducts = await productsCollection.find({ 
      discount: { $gt: 0 } 
    }).sort({ discount: -1 }).toArray();
    
    res.json(discountedProducts);
  } catch (err) {
    console.error('Error fetching discounted products:', err);
    res.status(500).json({ error: 'Failed to fetch discounted products' });
  }
});

// Get popular products (you can modify this based on your criteria)
app.get('/api/products/popular', async (req, res) => {
  try {
    const db = await connectToDB();
    const productsCollection = db.collection('products');
    
    // For now, return products with highest discount
    // You can modify this to use actual popularity metrics like views, orders, etc.
    const popularProducts = await productsCollection.find({ 
      discount: { $gt: 0 } 
    }).sort({ discount: -1 }).limit(10).toArray();
    
    res.json(popularProducts);
  } catch (err) {
    console.error('Error fetching popular products:', err);
    res.status(500).json({ error: 'Failed to fetch popular products' });
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
    const db = await connectToDB();
    const inquiriesCollection = db.collection('inquiries');
    
    const inquiries = await inquiriesCollection.find({ 
      userId: req.session.user.id 
    }).sort({ createdAt: -1 }).toArray();
    
    res.json(inquiries);
  } catch (err) {
    console.error('Error fetching user inquiries:', err);
    res.status(500).json({ error: 'Failed to fetch inquiries' });
  }
});

// ==================== USER PROFILE ROUTES ====================

app.get('/api/users/:id', requireUserAuth, async (req, res) => {
  try {
    const db = await connectToDB();
    const usersCollection = db.collection('users');
    
    const user = await usersCollection.findOne({ 
      _id: new ObjectId(req.params.id) 
    }, { projection: { password: 0 } });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if requesting user owns this profile
    if (req.session.user.id.toString() !== req.params.id && req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    res.json(user);
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

app.put('/api/users/:id', requireUserAuth, async (req, res) => {
  try {
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
    res.status(500).json({ error: 'Failed to update user' });
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
      'inquiry-management'
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
  
  🔍 Search Endpoints:
  ├── /api/products/search            - Search products
  ├── /api/products/search/suggestions - Real-time suggestions
  ├── /api/products/discounted        - Discounted products
  ├── /api/products/popular           - Popular products
  
  📊 Product Endpoints:
  ├── /api/products                   - All products
  ├── /api/products/category/:category - Products by category
  ├── /api/products/:id               - Single product
  
  👤 Auth Endpoints:
  ├── /api/auth/register              - User registration
  ├── /api/auth/login                 - User login
  ├── /api/auth/logout                - User logout
  ├── /api/auth/status                - Auth status
  
  📝 Inquiry Endpoints:
  ├── /api/inquiries                  - Submit inquiry
  ├── /api/user/inquiries             - User inquiries
  
  👤 User Endpoints:
  ├── /api/users/:id                  - Get user profile
  ├── /api/users/:id                  - Update user profile
  
  💪 Health Check:
  └── /api/health                     - Server health
  
  👤 User login: http://localhost:${PORT}/login
  🏪 Products page: http://localhost:${PORT}/categories.html
  
  ✅ Server is ready!`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Server shutting down gracefully...');
  const { closeDB } = require('../shared/database');
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
