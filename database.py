from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
from config import config
from logger import get_logger

logger = get_logger('database')

class Database:
    """Database connection and operations handler."""
    
    _instance = None
    
    def __new__(cls):
        """Implement singleton pattern for database connection."""
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Initialize MongoDB connection if not already initialized."""
        if self._initialized:
            return
            
        self.client = None
        self.db = None
        self.scan_collection = None
        self.user_collection = None
        
        self.connect()
        self._initialized = True
    
    def connect(self):
        """Establish connection to MongoDB."""
        try:
            logger.info("Connecting to MongoDB...")
            self.client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=5000)
            
            # Test connection
            self.client.admin.command('ping')
            
            self.db = self.client[config.MONGO_DB_NAME]
            self.scan_collection = self.db[config.MONGO_SCAN_COLLECTION]
            self.user_collection = self.db[config.MONGO_USER_COLLECTION]
            
            logger.info("Successfully connected to MongoDB")
        except ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
        except OperationFailure as e:
            logger.error(f"MongoDB authentication failed: {e}")
            raise
    
    def close(self):
        """Close the MongoDB connection."""
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed")
    
    def get_scan_collection(self):
        """Get the scan collection."""
        return self.scan_collection
    
    def get_user_collection(self):
        """Get the user collection."""
        return self.user_collection
    
    def insert_scan_result(self, scan_data):
        """Insert scan result into the scan collection."""
        try:
            result = self.scan_collection.insert_one(scan_data)
            logger.info(f"Inserted scan result with ID: {result.inserted_id}")
            return result.inserted_id
        except Exception as e:
            logger.error(f"Error inserting scan result: {e}")
            raise
    
    def find_scan_result(self, query):
        """Find scan results matching the query."""
        try:
            return self.scan_collection.find(query)
        except Exception as e:
            logger.error(f"Error finding scan results: {e}")
            raise
    
    def update_scan_result(self, query, update):
        """Update scan results matching the query."""
        try:
            result = self.scan_collection.update_one(query, update)
            logger.info(f"Updated {result.modified_count} scan result(s)")
            return result.modified_count
        except Exception as e:
            logger.error(f"Error updating scan result: {e}")
            raise
    
    def delete_scan_result(self, query):
        """Delete scan results matching the query."""
        try:
            result = self.scan_collection.delete_many(query)
            logger.info(f"Deleted {result.deleted_count} scan result(s)")
            return result.deleted_count
        except Exception as e:
            logger.error(f"Error deleting scan results: {e}")
            raise
    
    def find_user(self, query):
        """Find user matching the query."""
        try:
            return self.user_collection.find_one(query)
        except Exception as e:
            logger.error(f"Error finding user: {e}")
            raise

# Create a global database instance
db = Database()
