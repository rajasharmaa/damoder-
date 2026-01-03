// setup-persistence.js - Run this to setup persistent sessions
const { MongoClient } = require('mongodb');

async function setupPersistentSessions() {
  const uri = process.env.MONGODB_URI;
  const client = new MongoClient(uri);
  
  try {
    await client.connect();
    console.log('✅ Connected to MongoDB');
    
    const db = client.db();
    
    // Create TTL index for sessions (auto-delete after 30 days)
    const sessions = db.collection('user_sessions');
    await sessions.createIndex(
      { expires: 1 },
      { expireAfterSeconds: 30 * 24 * 60 * 60 } // 30 days
    );
    
    console.log('✅ Created TTL index for sessions');
    
    // Create indexes for users collection
    const users = db.collection('users');
    await users.createIndex({ email: 1 }, { unique: true });
    await users.createIndex({ resetToken: 1 });
    await users.createIndex({ resetTokenExpiry: 1 });
    
    console.log('✅ Created indexes for users collection');
    
    // Create indexes for products collection
    const products = db.collection('products');
    await products.createIndex({ category: 1 });
    await products.createIndex({ discount: -1 });
    await products.createIndex({ createdAt: -1 });
    await products.createIndex({ 
      name: 'text', 
      description: 'text', 
      category: 'text', 
      material: 'text' 
    });
    
    console.log('✅ Created indexes for products collection');
    
    // Create indexes for inquiries collection
    const inquiries = db.collection('inquiries');
    await inquiries.createIndex({ email: 1 });
    await inquiries.createIndex({ userId: 1 });
    await inquiries.createIndex({ createdAt: -1 });
    
    console.log('✅ Created indexes for inquiries collection');
    
    console.log('\n🎉 Database setup complete!');
    console.log('✅ Persistent sessions are now enabled');
    console.log('✅ Sessions will auto-expire after 30 days');
    console.log('✅ Users will stay logged in across browser sessions');
    
  } catch (error) {
    console.error('❌ Setup failed:', error);
  } finally {
    await client.close();
  }
}

setupPersistentSessions();
