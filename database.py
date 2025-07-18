import asyncio
from datetime import datetime, timedelta
import jwt
from typing import Optional, Dict, Any, List, Tuple, Callable
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, OperationFailure, ServerSelectionTimeoutError
from pymongo.collection import Collection
from pymongo.results import InsertOneResult, UpdateResult, DeleteResult
import backoff
import redis
from functools import wraps
import json
from bson import ObjectId
import secrets
import hashlib
import certifi
from config import config
from logger import get_logger

# Custom JSON encoder to handle MongoDB ObjectId and other non-serializable types
class MongoJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, '__str__'):
            return str(obj)
        return super().default(obj)

def rate_limit(
    max_calls: int,
    time_window: int,
    key_prefix: str
):
    """Rate limiting decorator for database operations."""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            if not self.redis_client:
                return await func(self, *args, **kwargs)
                
            # Generate rate limit key
            key = f"{config.REDIS_PREFIX}:ratelimit:{key_prefix}:{func.__name__}"
            
            try:
                # Check current call count
                current = int(self.redis_client.get(key) or 0)
                
                if current >= max_calls:
                    logger.warning(f"Rate limit exceeded for {func.__name__}")
                    raise OperationError(f"Rate limit exceeded. Try again in {time_window} seconds.")
                
                # Increment call count
                pipe = self.redis_client.pipeline()
                pipe.incr(key)
                pipe.expire(key, time_window)
                pipe.execute()
                
                return await func(self, *args, **kwargs)
            except redis.RedisError as e:
                logger.error(f"Rate limit check failed: {e}")
                return await func(self, *args, **kwargs)
        return wrapper
    return decorator

logger = get_logger('database')

class DatabaseError(Exception):
    """Base exception for database errors."""
    pass

class ConnectionError(DatabaseError):
    """Exception for connection-related errors."""
    pass

class AuthenticationError(DatabaseError):
    """Exception for authentication-related errors."""
    pass

class OperationError(DatabaseError):
    """Exception for operation-related errors."""
    pass

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
        """Initialize MongoDB and Redis connections if not already initialized."""
        if self._initialized:
            return
            
        self.client = None
        self.async_client = None
        self.db = None
        self.async_db = None
        self.scan_collection = None
        self.user_collection = None
        self.redis_client = None
        self.conn_options = None  # Store connection options as instance variable
        self._initialized = True
        
        # Initialize connection pools
        self.connect()
        self._init_redis()
        
    def _init_redis(self):
        """Initialize Redis connection for caching."""
        try:
            self.redis_client = redis.from_url(
                config.REDIS_URL,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
                retry_on_error=[redis.TimeoutError, redis.ConnectionError],
                health_check_interval=30,
                max_connections=10
            )
            self.redis_client.ping()
            logger.info("Successfully connected to Redis")
        except redis.RedisError as e:
            logger.warning(f"Failed to connect to Redis, caching disabled: {e}")
            self.redis_client = None
            
    def _cache_key(self, prefix: str, *args) -> str:
        """Generate cache key from prefix and arguments."""
        key_parts = [str(arg) for arg in args]
        key_string = f"{prefix}:{{':'.join(key_parts)}}"
        return f"{config.REDIS_PREFIX}:{hashlib.sha256(key_string.encode()).hexdigest()}"
        
    async def _get_cache(self, key: str) -> Optional[Dict]:
        """Get data from cache."""
        if not self.redis_client:
            return None
        try:
            data = self.redis_client.get(key)
            return json.loads(data) if data else None
        except (redis.RedisError, json.JSONDecodeError) as e:
            logger.warning(f"Cache get error: {e}")
            return None
            
    async def _set_cache(self, key: str, value: Any, expire: int = 3600) -> bool:
        """Set data in cache with expiration."""
        if not self.redis_client:
            return False
        try:
            return self.redis_client.setex(
                key,
                expire,
                json.dumps(value, default=str)
            )
        except (redis.RedisError, TypeError) as e:
            logger.warning(f"Cache set error: {e}")
            return False
            
    def get_pool_metrics(self) -> Dict[str, Any]:
        """Get detailed connection pool metrics."""
        if not self.client:
            return {}
            
        pool_info = self.client.get_pool_info()
        return {
            **self.pool_metrics,
            'current_pool_size': pool_info.get('pool_size', 0),
            'active_connections': pool_info.get('active_sockets', 0),
            'available_connections': pool_info.get('available_sockets', 0),
            'max_pool_size': config.MONGO_POOL_SIZE,
            'pool_utilization': round(
                (pool_info.get('active_sockets', 0) / config.MONGO_POOL_SIZE) * 100, 2
            ) if config.MONGO_POOL_SIZE > 0 else 0,
            'last_pool_reset': self.pool_metrics.get('pool_cleared_time'),
            'connection_errors': self.pool_metrics.get('connection_errors', 0)
        }
        
    async def monitor_pool_health(self):
        """Monitor connection pool health and take corrective actions."""
        while True:
            try:
                metrics = self.get_pool_metrics()
                
                # Check pool utilization
                if metrics.get('pool_utilization', 0) > 80:
                    logger.warning("High pool utilization detected")
                    self.pool_metrics['max_pool_size_reached'] = True
                
                # Check for stale connections
                if metrics.get('active_connections', 0) > metrics.get('available_connections', 0) * 2:
                    logger.warning("Possible connection leak detected")
                    await self.clear_stale_connections()
                
                # Log metrics periodically
                if metrics.get('pool_utilization', 0) > 60:
                    logger.info(f"Pool health metrics: {json.dumps(metrics, indent=2)}")
                
                await asyncio.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Error monitoring pool health: {e}")
                await asyncio.sleep(30)  # Retry after 30 seconds on error
                
    async def clear_stale_connections(self):
        """Clear stale connections from the pool."""
        try:
            if self.client:
                self.client.close()
                self.client = MongoClient(config.MONGO_URI, **self.conn_options)
                self.pool_metrics['pool_cleared_time'] = datetime.utcnow()
                self.pool_metrics['connections_closed'] += 1
                logger.info("Successfully cleared stale connections")
        except Exception as e:
            logger.error(f"Error clearing stale connections: {e}")
            self.pool_metrics['connection_errors'] = self.pool_metrics.get('connection_errors', 0) + 1
            
    async def start_health_monitor(self):
        """Start the connection pool health monitoring task."""
        asyncio.create_task(self.monitor_pool_health())
    
    @backoff.on_exception(
        backoff.expo,
        (ConnectionFailure, ServerSelectionTimeoutError),
        max_tries=10,
        max_time=60,
        jitter=None
    )
    def connect(self):
        """Establish connection to MongoDB with retry mechanism."""
        try:
            logger.info("Connecting to MongoDB...")
            # MongoDB Atlas connection options
            self.conn_options = {
                'tlsCAFile': certifi.where()
            }
            

            # Monitor connection pool metrics
            self.pool_metrics = {
                'connections_created': 0,
                'connections_closed': 0,
                'pool_cleared_time': None,
                'max_pool_size_reached': False
            }
            
            # Synchronous client
            self.client = MongoClient(config.MONGO_URI, **self.conn_options)
            
            # Async client
            self.async_client = AsyncIOMotorClient(config.MONGO_URI, **self.conn_options)
            
            # Test connection
            self.client.admin.command('ping')
            
            # Initialize databases and collections
            self.db = self.client[config.MONGO_DB_NAME]
            self.async_db = self.async_client[config.MONGO_DB_NAME]
            self.scan_collection = self.db[config.MONGO_SCAN_COLLECTION]
            self.user_collection = self.db[config.MONGO_USER_COLLECTION]
            self.target_collection = self.db[config.MONGO_TARGET_COLLECTION]  # Target Collection
            self.subdomain_collection = self.db['subdomains']  # Subdomain Collection
            
            # Create indexes
            self._create_indexes()
            
            logger.info("Successfully connected to MongoDB")
        except ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise ConnectionError(f"Database connection failed: {e}")
        except OperationFailure as e:
            logger.error(f"MongoDB authentication failed: {e}")
            raise AuthenticationError(f"Database authentication failed: {e}")
    
    def _create_indexes(self):
        """Create necessary indexes for collections."""
        try:
            # Scan collection indexes
            self.scan_collection.create_index([("domain", ASCENDING)])
            self.scan_collection.create_index([("created_at", DESCENDING)])
            self.scan_collection.create_index([("user_id", ASCENDING)])
            self.scan_collection.create_index([("status", ASCENDING)])
            
            # User collection indexes
            self.user_collection.create_index([("username", ASCENDING)], unique=True)
            self.user_collection.create_index([("email", ASCENDING)], unique=True)
            self.user_collection.create_index([("api_key", ASCENDING)], unique=True, sparse=True)
            
            # Target collection indexes
            self.target_collection.create_index([("_id", ASCENDING)])  # Corrected line: removed unique=True
            self.target_collection.create_index([("domain", ASCENDING)])
            self.target_collection.create_index([("user_id", ASCENDING)])
            
            # Subdomain collection indexes
            self.subdomain_collection.create_index([("domain", ASCENDING)])
            self.subdomain_collection.create_index([("created_at", DESCENDING)])
            self.subdomain_collection.create_index([("target_id", ASCENDING)])
        
            logger.info("Database indexes created successfully")
        except Exception as e:
            logger.error(f"Error creating indexes: {e}")
            raise OperationError(f"Failed to create indexes: {e}")


    async def close(self):
        """Close all database connections."""
        if self.client:
            self.client.close()
        if self.async_client:
            self.async_client.close()
        logger.info("All database connections closed")
        
    async def get_scan_count(self, target_id: str) -> int:
        """Get the total number of scans for a target."""
        try:
            count = await self.async_db[config.MONGO_SCAN_COLLECTION].count_documents({"target_id": target_id})
            return count
        except Exception as e:
            logger.error(f"Error getting scan count: {e}")
            return 0
    
    async def ping(self) -> bool:
        """Check database connectivity."""
        try:
            self.client.admin.command('ping')
            return True
        except Exception as e:
            logger.error(f"Database ping failed: {e}")
            return False
    
    async def validate_token(self, token: str) -> Optional[Dict]:
        """Validate JWT token and return user data."""
        try:
            payload = jwt.decode(
                token,
                config.JWT_SECRET_KEY,
                algorithms=['HS256']
            )
            
            user = await self.find_user({"_id": payload['sub']})
            if not user:
                return None
                
            return user
        except jwt.ExpiredSignatureError:
            logger.warning("Expired token received")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token received: {e}")
            return None
    
    async def create_token(self, user_id: str, token_type: str = 'access') -> str:
        """Create a new JWT token."""
        now = datetime.utcnow()
        
        if token_type == 'access':
            expires_delta = config.JWT_ACCESS_TOKEN_EXPIRES
        else:
            expires_delta = config.JWT_REFRESH_TOKEN_EXPIRES
            
        payload = {
            'sub': str(user_id),
            'type': token_type,
            'iat': now,
            'exp': now + expires_delta
        }
        
        return jwt.encode(
            payload,
            config.JWT_SECRET_KEY,
            algorithm='HS256'
        )
    
    @backoff.on_exception(
        backoff.expo,
        (ConnectionFailure, OperationFailure),
        max_tries=3
    )
    async def store_scan_results(self, target_id: str, results: Dict) -> str:
        """Store scan results with retry mechanism."""
        try:
            now = datetime.utcnow()
            results['created_at'] = now
            results['updated_at'] = now
            results['target_id'] = target_id
            
            # Generate a unique ID for this scan
            scan_id = results.get('request_id', secrets.token_hex(16))
            
            # Check if a scan with this ID already exists
            existing = await self.async_db[config.MONGO_SCAN_COLLECTION].find_one(
                {"request_id": scan_id}
            )
            
            if existing:
                # Update existing record instead of inserting a new one
                update_result = await self.async_db[config.MONGO_SCAN_COLLECTION].update_one(
                    {"_id": existing["_id"]},
                    {"$set": results}
                )
                logger.info(f"Updated scan results with ID: {existing['_id']}")
                return str(existing['_id'])
            else:
                # Insert new record
                result = await self.async_db[config.MONGO_SCAN_COLLECTION].insert_one(results)
                logger.info(f"Stored scan results with ID: {result.inserted_id}")
                return str(result.inserted_id)
                
        except Exception as e:
            logger.error(f"Error storing scan results: {e}")
            raise OperationError(f"Failed to store scan results: {e}")
    
    @backoff.on_exception(
        backoff.expo,
        (ConnectionFailure, OperationFailure),
        max_tries=3
    )
    async def store_subdomain_results(self, target_id: str, domain: str, subdomains: List[str], urls: Dict) -> str:
        """Store subdomain scan results with retry mechanism."""
        try:
            now = datetime.utcnow()
            subdomain_data = {
                'target_id': target_id,
                'domain': domain,
                'subdomains': subdomains,
                'urls': urls,
                'created_at': now,
                'updated_at': now,
                'scan_timestamp': now.isoformat()
            }
            
            # Check if we already have results for this target
            existing = await self.async_db['subdomains'].find_one({'target_id': target_id})
            
            if existing:
                # Update existing record
                result = await self.async_db['subdomains'].update_one(
                    {'target_id': target_id},
                    {'$set': subdomain_data}
                )
                logger.info(f"Updated subdomain results for target: {target_id}")
                return str(existing['_id'])
            else:
                # Insert new record
                result = await self.async_db['subdomains'].insert_one(subdomain_data)
                logger.info(f"Stored subdomain results with ID: {result.inserted_id}")
                return str(result.inserted_id)
                
        except Exception as e:
            logger.error(f"Error storing subdomain results: {e}")
            raise OperationError(f"Failed to store subdomain results: {e}")
    
    async def get_subdomain_results(self, target_id: str) -> Optional[Dict]:
        """Get subdomain scan results for a target."""
        try:
            results = await self.async_db['subdomains'].find_one({'target_id': target_id})
            return results
        except Exception as e:
            logger.error(f"Error getting subdomain results: {e}")
            return None
    
    @backoff.on_exception(
        backoff.expo,
        (ConnectionFailure, OperationFailure),
        max_tries=3
    )
    async def validate_api_key(self, api_key: str) -> tuple[Optional[Dict], Optional[str], Optional[str]]:
        """
        Validate API key and return user data.
        Returns: (user_data, error_code, error_message)
        """
        try:
            # Check if API key is provided
            if not api_key:
                return None, "invalid_key", "No API key provided"
            
            # Check if event loop is running
            try:
                loop = asyncio.get_event_loop()
                if not loop.is_running():
                    # Try to create a new event loop if the current one is closed
                    asyncio.set_event_loop(asyncio.new_event_loop())
                    logger.warning("Created new event loop for API key validation")
            except RuntimeError:
                # If we can't get the event loop, create a new one
                asyncio.set_event_loop(asyncio.new_event_loop())
                logger.warning("Created new event loop for API key validation")
            
            # Check if database connection is active, reconnect if needed
            if self.async_client is None or self.async_db is None:
                logger.info("Reconnecting to MongoDB for API key validation")
                self.connect()
            
            # Find user by API key
            try:
                user = await self.async_db[config.MONGO_USER_COLLECTION].find_one({"api_key": api_key})
            except Exception as db_error:
                # If database operation fails, try to reconnect and retry once
                if "Event loop is closed" in str(db_error):
                    logger.warning("Event loop closed during database operation, reconnecting")
                    self.connect()
                    user = await self.async_db[config.MONGO_USER_COLLECTION].find_one({"api_key": api_key})
                else:
                    raise
            
            # Validate the user and API key
            if not user:
                return None, "invalid_key", "API key is invalid"

            # Check if API key is active
            if user.get('api_key_status', 'active') != 'active':
                return None, "inactive_key", "API key is inactive"

            # Check if API key matches the one in headers
            if user.get('api_key') != api_key:
                return None, "invalid_key", "API key mismatch"

            return user, None, None
        
        except Exception as e:
            logger.error(f"Error validating API key: {e}")
            # Provide a more user-friendly error message for event loop issues
            if "Event loop is closed" in str(e):
                return None, "validation_error", "Server connection error. Please try again."
            return None, "validation_error", str(e)

    async def find_user(self, query: Dict) -> Optional[Dict]:
        """Find user matching the query with caching."""
        cache_key = self._cache_key('user', json.dumps(query, sort_keys=True))
        
        # Try to get from cache first
        if cached_user := await self._get_cache(cache_key):
            logger.debug("User found in cache")
            return cached_user
            
        try:
            # Ensure connection is active
            if self.async_client is None or self.async_db is None:
                logger.info("Reconnecting to MongoDB...")
                self.async_client = AsyncIOMotorClient(config.MONGO_URI, **self.conn_options)
                self.async_db = self.async_client[config.MONGO_DB_NAME]

            user = await self.async_db[config.MONGO_USER_COLLECTION].find_one(query)
            if user:
                # Cache user data for 5 minutes
                await self._set_cache(cache_key, user, 300)
            return user
        except Exception as e:
            logger.error(f"Error finding user: {e}", exc_info=True)
            # Try to reconnect on connection errors
            if "Event loop is closed" in str(e):
                # Close existing connections first
                if self.async_client:
                    await self.async_client.close()
                
                try:
                    # Reconnect
                    self.connect()
                    user = await self.async_db[config.MONGO_USER_COLLECTION].find_one(query)
                    if user:
                        await self._set_cache(cache_key, user, 300)
                    return user
                except Exception as reconnect_error:
                    logger.error(f"Reconnection failed: {reconnect_error}")
                    self.async_client = None
                    self.async_db = None
            raise OperationError(f"Failed to find user: {str(e)}")
    
    @backoff.on_exception(
        backoff.expo,
        (ConnectionFailure, OperationFailure),
        max_tries=3
    )
    async def get_scan_results(
        self,
        query: Dict,
        limit: int = 100,
        skip: int = 0,
        sort: List = None
    ) -> Tuple[List[Dict], int]:
        """Get scan results with pagination and total count."""
        cache_key = self._cache_key(
            'scan_results',
            json.dumps(query, sort_keys=True),
            limit,
            skip,
            json.dumps(sort) if sort else 'none'
        )
        
        # Try to get from cache first
        if cached_results := await self._get_cache(cache_key):
            logger.debug("Scan results found in cache")
            return cached_results['results'], cached_results['total']
            
        try:
            # Get total count for pagination
            total = await self.async_db[config.MONGO_SCAN_COLLECTION].count_documents(query)
            
            # Get paginated results
            cursor = self.async_db[config.MONGO_SCAN_COLLECTION].find(
                query,
                # Add projection to exclude large fields if needed
                projection={
                    'raw_data': 0,  # Exclude raw scan data
                    'detailed_logs': 0  # Exclude detailed logs
                }
            )
            
            if sort:
                cursor = cursor.sort(sort)
            cursor = cursor.skip(skip).limit(limit)
            
            results = await cursor.to_list(length=None)
            
            # Cache results for 2 minutes (shorter time for scan results as they change more frequently)
            cache_data = {'results': results, 'total': total}
            await self._set_cache(cache_key, cache_data, 120)
            
            return results, total
        except Exception as e:
            logger.error(f"Error retrieving scan results: {e}", exc_info=True)
            raise OperationError(f"Failed to retrieve scan results: {str(e)}")
    
    async def update_scan_status(
        self,
        scan_id: str,
        status: str,
        additional_data: Dict = None
    ) -> bool:
        """Update scan status and optional additional data."""
        try:
            update_data = {
                "$set": {
                    "status": status,
                    "updated_at": datetime.utcnow()
                }
            }
            
            if additional_data:
                if isinstance(additional_data, dict):
                    update_data["$set"].update(additional_data)
                else:
                    update_data["$set"]["request_id"] = additional_data
            
            result = await self.async_db[config.MONGO_SCAN_COLLECTION].update_one(
                {"_id": scan_id},
                update_data
            )
            
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error updating scan status: {e}")
            raise OperationError(f"Failed to update scan status: {e}")
    
    async def renew_api_key(self, api_key: str, days: int = 30) -> tuple[Optional[Dict], Optional[str], Optional[str]]:
        """
        Manually renew an API key for the specified number of days.
        Returns: (updated_user, error_code, error_message)
        """
        try:
            # First validate the current key
            user, error_code, error_message = await self.validate_api_key(api_key)
            if not user and error_code != "expired_key":  # Allow renewal of expired keys
                return None, error_code, error_message

            # Update API key details
            new_expiry = datetime.utcnow() + timedelta(days=days)
            update_result = await self.async_db[config.MONGO_USER_COLLECTION].update_one(
                {"api_key": api_key},
                {
                    "$set": {
                        "api_key_details.expires_at": new_expiry,
                        "api_key_details.status": "active",
                        "api_key_details.last_renewed": datetime.utcnow()
                    }
                }
            )

            if update_result.modified_count == 0:
                return None, "renewal_failed", "Failed to renew API key"

            # Get updated user data
            updated_user = await self.find_user({"api_key": api_key})
            return updated_user, None, None

        except Exception as e:
            logger.error(f"Error renewing API key: {e}")
            return None, "system_error", "Error during API key renewal"

    async def cleanup_old_scans(self, days: int = 30) -> int:
        """Clean up scan results older than specified days."""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            result = await self.async_db[config.MONGO_SCAN_COLLECTION].delete_many({
                "created_at": {"$lt": cutoff_date}
            })
            
            logger.info(f"Cleaned up {result.deleted_count} old scan results")
            return result.deleted_count
        except Exception as e:
            logger.error(f"Error cleaning up old scans: {e}")
            raise OperationError(f"Failed to clean up old scans: {e}")

    async def get_target_by_id(self, target_id: str) -> Optional[Dict]:
        """Retrieve a target by its ID."""
        try:
            target = await self.async_db[config.MONGO_TARGET_COLLECTION].find_one({"_id": target_id})
            return target
        except Exception as e:
            logger.error(f"Error retrieving target: {e}")
            return None

# Create a global database instance
db = Database()
