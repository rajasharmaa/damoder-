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

module.exports = { connectToDB, closeDB };