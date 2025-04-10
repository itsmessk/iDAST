// Create application user and set permissions
db.createUser({
  user: process.env.MONGO_USER || 'secpro_user',
  pwd: process.env.MONGO_PASSWORD,
  roles: [
    { role: 'readWrite', db: process.env.MONGO_INITDB_DATABASE || 'secpro' }
  ]
});

// Switch to application database
db = db.getSiblingDB(process.env.MONGO_INITDB_DATABASE || 'secpro');

// Create collections with schema validation
db.createCollection('scans', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['target_url', 'scan_type', 'status', 'created_at'],
      properties: {
        target_url: { bsonType: 'string' },
        scan_type: { bsonType: 'string' },
        status: { bsonType: 'string' },
        created_at: { bsonType: 'date' },
        completed_at: { bsonType: 'date' },
        results: { bsonType: 'object' },
        error: { bsonType: 'string' }
      }
    }
  }
});

db.createCollection('users', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['username', 'password_hash', 'created_at', 'role'],
      properties: {
        username: { bsonType: 'string' },
        password_hash: { bsonType: 'string' },
        role: { bsonType: 'string' },
        created_at: { bsonType: 'date' },
        last_login: { bsonType: 'date' }
      }
    }
  }
});

// Create indexes
db.scans.createIndex({ "target_url": 1 });
db.scans.createIndex({ "created_at": 1 });
db.scans.createIndex({ "status": 1 });
db.scans.createIndex({ "scan_type": 1 });

db.users.createIndex({ "username": 1 }, { unique: true });
db.users.createIndex({ "created_at": 1 });

// Create TTL index for completed scans (30 days)
db.scans.createIndex({ "completed_at": 1 }, { expireAfterSeconds: 2592000 });