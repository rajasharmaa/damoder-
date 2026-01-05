const { MongoClient, ServerApiVersion } = require('mongodb');

const uri = process.env.MONGODB_URI || "mongodb+srv://rajat888sharma111_db_user:rajat888@cluster0.c6jicll.mongodb.net/?appName=Cluster0";

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
  tls: true,
  maxPoolSize: 50,
  minPoolSize: 5,
  maxIdleTimeMS: 30000,
  connectTimeoutMS: 10000,
  socketTimeoutMS: 45000,
  retryWrites: true,
  retryReads: true,
  w: 'majority',
  readPreference: 'primary'
});

let dbConnection = null;

async function connectToDB() {
  try {
    if (!dbConnection) {
      console.log("🔌 Connecting to MongoDB Atlas...");
      await client.connect();
      dbConnection = client.db('damodarTraders');
      console.log("✅ Connected to MongoDB Atlas!");
    }
    return dbConnection;
  } catch (err) {
    console.error("❌ MongoDB connection error:", err.message);
    throw err;
  }
}

async function closeDB() {
  try {
    await client.close();
    console.log("✅ MongoDB connection closed");
    dbConnection = null;
  } catch (err) {
    console.error("❌ Error closing MongoDB connection:", err);
  }
}

/**
 * SAFE index creation that works with apiStrict: true
 * Uses createIndexes() instead of createIndex() with proper syntax
 */
async function setupDatabaseIndexes() {
  try {
    const db = await connectToDB();
    
    console.log("🔄 Setting up database indexes...");
    
    // Use createIndexes() API which is compatible with apiStrict: true
    await Promise.all([
      // Products collection indexes
      db.collection('products').createIndexes([
        {
          name: "active_createdAt_idx",
          key: { active: 1, createdAt: -1 }
        },
        {
          name: "category_active_idx",
          key: { category: 1, active: 1 }
        },
        {
          name: "name_idx",
          key: { name: 1 }
        },
        {
          name: "tags_idx",
          key: { tags: 1 }
        }
      ]),
      
      // Inquiries collection indexes
      db.collection('inquiries').createIndexes([
        {
          name: "userId_createdAt_idx",
          key: { userId: 1, createdAt: -1 }
        },
        {
          name: "email_createdAt_idx",
          key: { email: 1, createdAt: -1 }
        },
        {
          name: "status_createdAt_idx",
          key: { status: 1, createdAt: -1 }
        }
      ]),
      
      // Users collection indexes
      db.collection('users').createIndexes([
        {
          name: "email_unique_idx",
          key: { email: 1 },
          unique: true
        },
        {
          name: "resetToken_idx",
          key: { resetToken: 1 },
          sparse: true
        },
        {
          name: "resetTokenExpiry_idx",
          key: { resetTokenExpiry: 1 },
          expireAfterSeconds: 3600,
          sparse: true
        }
      ]),
      
      // Sessions collection indexes (for TTL)
      db.collection('sessions').createIndexes([
        {
          name: "expires_ttl_idx",
          key: { expires: 1 },
          expireAfterSeconds: 0
        },
        {
          name: "session_user_id_idx",
          key: { "session.user.id": 1 },
          sparse: true
        }
      ])
    ]);
    
    console.log("✅ Database indexes created successfully!");
    
    // Verify indexes exist
    const collections = ['products', 'users', 'inquiries', 'sessions'];
    for (const collectionName of collections) {
      try {
        const indexes = await db.collection(collectionName).indexes();
        console.log(`📊 ${collectionName} has ${indexes.length} indexes`);
      } catch (err) {
        console.log(`⚠️ Could not check indexes for ${collectionName}:`, err.message);
      }
    }
    
  } catch (err) {
    console.error("❌ Failed to setup database indexes:", err.message);
    
    // Try a simpler approach if the above fails
    if (err.message.includes('apiStrict')) {
      console.warn("⚠️ apiStrict mode detected. Creating minimal indexes...");
      await createMinimalIndexes();
    }
  }
}

/**
 * Minimal index creation for apiStrict environments
 */
async function createMinimalIndexes() {
  try {
    const db = await connectToDB();
    
    // Create only essential indexes
    await db.collection('users').createIndex({ email: 1 }, { unique: true });
    await db.collection('sessions').createIndex({ expires: 1 }, { expireAfterSeconds: 0 });
    await db.collection('products').createIndex({ active: 1, createdAt: -1 });
    await db.collection('inquiries').createIndex({ createdAt: -1 });
    
    console.log("✅ Minimal indexes created");
  } catch (err) {
    console.error("❌ Failed to create minimal indexes:", err.message);
  }
}

module.exports = { 
  connectToDB, 
  closeDB,
  setupDatabaseIndexes
};
