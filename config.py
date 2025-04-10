import os
import secrets
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class BaseConfig:
    """Base configuration settings for the application."""
    
    # Application Version
    VERSION = "1.0.0"
    
    # Environment
    FLASK_ENV = os.getenv('FLASK_ENV', 'production')
    
    # MongoDB Configuration
    MONGO_HOST = os.getenv('MONGO_HOST', 'localhost')
    MONGO_PORT = int(os.getenv('MONGO_PORT', 27017))
    MONGO_USER = os.getenv('MONGO_USER', '')
    MONGO_PASSWORD = os.getenv('MONGO_PASSWORD', '')
    MONGO_DB_NAME = os.getenv('MONGO_DB_NAME', 'secpro')
    MONGO_SCAN_COLLECTION = os.getenv('MONGO_SCAN_COLLECTION', 'scan')
    MONGO_USER_COLLECTION = os.getenv('MONGO_USER_COLLECTION', 'users')
    MONGO_POOL_SIZE = int(os.getenv('MONGO_POOL_SIZE', 50))  # Reduced pool size
    MONGO_CONNECT_TIMEOUT = int(os.getenv('MONGO_CONNECT_TIMEOUT', 3000))  # Reduced timeout
    MONGO_MAX_IDLE_TIME = int(os.getenv('MONGO_MAX_IDLE_TIME', 15000))  # 15 seconds idle time
    
    @property
    def MONGO_URI(self):
        """Construct MongoDB URI with authentication if credentials are provided."""
        if self.MONGO_USER and self.MONGO_PASSWORD:
            return f"mongodb://{self.MONGO_USER}:{self.MONGO_PASSWORD}@{self.MONGO_HOST}:{self.MONGO_PORT}"
        return f"mongodb://{self.MONGO_HOST}:{self.MONGO_PORT}"
    
    # Redis Configuration
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    REDIS_PREFIX = os.getenv('REDIS_PREFIX', 'secpro')
    
    # API Configuration
    API_PORT = int(os.getenv('PORT', 3000))
    API_HOST = os.getenv('API_HOST', '0.0.0.0')
    DEBUG_MODE = False
    
    # CORS Configuration
    ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', '*').split(',')
    CORS_MAX_AGE = int(os.getenv('CORS_MAX_AGE', 600))
    
    # Scanning Configuration
    SCAN_TIMEOUT = int(os.getenv('SCAN_TIMEOUT', 300))  # Default timeout in seconds
    TOTAL_SCAN_TIMEOUT = int(os.getenv('TOTAL_SCAN_TIMEOUT', 600))  # Total scan timeout
    MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', 10))
    RESULTS_DIR = os.getenv('RESULTS_DIR', 'results')
    SCAN_RATE_LIMIT = os.getenv('SCAN_RATE_LIMIT', "5 per minute")
    
    # Connection Pool Configuration
    MAX_CONCURRENT_CONNECTIONS = int(os.getenv('MAX_CONCURRENT_CONNECTIONS', 100))
    CONNECTION_TIMEOUT = int(os.getenv('CONNECTION_TIMEOUT', 30))
    POOL_TTL = int(os.getenv('POOL_TTL', 300))
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = os.getenv('LOG_FORMAT', '%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    LOG_FILE = os.getenv('LOG_FILE', 'logs/security_api.log')
    LOG_MAX_BYTES = int(os.getenv('LOG_MAX_BYTES', 10485760))  # 10MB
    LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', 5))
    
    # Scanner-specific Configuration
    SQLMAP_ARGS = os.getenv('SQLMAP_ARGS', '--batch --random-agent')
    DALFOX_ARGS = os.getenv('DALFOX_ARGS', '--silence --skip-bav')
    
    # Security Configuration
    ENABLE_AUTH = True
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', secrets.token_hex(32))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    
    # Performance Configuration
    WORKER_PROCESSES = int(os.getenv('WORKER_PROCESSES', 4))
    WORKER_THREADS = int(os.getenv('WORKER_THREADS', 2))
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', 120))
    
    # Rate Limiting
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', 60))
    RATE_LIMIT_BURST = int(os.getenv('RATE_LIMIT_BURST', 100))
    
    # Timezone Configuration
    SERVER_TIMEZONE = os.getenv('SERVER_TIMEZONE', 'UTC')
    OUTPUT_TIMEZONE = os.getenv('OUTPUT_TIMEZONE', 'UTC')
    
    # User Agent
    USER_AGENT = os.getenv('USER_AGENT', f'SecPro-Scanner/{VERSION} (Security Analysis Tool)')
    
    # Cache Configuration
    CACHE_TYPE = os.getenv('CACHE_TYPE', 'redis')
    CACHE_REDIS_URL = REDIS_URL
    CACHE_DEFAULT_TIMEOUT = int(os.getenv('CACHE_DEFAULT_TIMEOUT', 3600))
    
    # Health Check Configuration
    HEALTH_CHECK_INTERVAL = int(os.getenv('HEALTH_CHECK_INTERVAL', 30))
    HEALTH_CHECK_TIMEOUT = int(os.getenv('HEALTH_CHECK_TIMEOUT', 10))
    HEALTH_CHECK_RETRIES = int(os.getenv('HEALTH_CHECK_RETRIES', 3))


class DevelopmentConfig(BaseConfig):
    """Development configuration settings."""
    DEBUG_MODE = True
    ENABLE_AUTH = os.getenv('ENABLE_AUTH', 'True').lower() == 'true'
    RATE_LIMIT_ENABLED = False
    SESSION_COOKIE_SECURE = False
    ALLOWED_ORIGINS = ['*']
    LOG_LEVEL = 'DEBUG'


class TestingConfig(BaseConfig):
    """Testing configuration settings."""
    DEBUG_MODE = True
    MONGO_DB_NAME = 'secpro_test'
    RESULTS_DIR = 'tests/scan_results'
    LOG_FILE = 'tests/logs/security_api.log'
    ENABLE_AUTH = False
    RATE_LIMIT_ENABLED = False
    SESSION_COOKIE_SECURE = False
    ALLOWED_ORIGINS = ['*']
    REDIS_URL = 'memory://'
    CACHE_TYPE = 'simple'


class ProductionConfig(BaseConfig):
    """Production configuration settings."""
    # Ensure all security features are enabled
    DEBUG_MODE = False
    ENABLE_AUTH = True
    
    # More conservative resource usage
    MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', 5))
    MAX_CONCURRENT_CONNECTIONS = int(os.getenv('MAX_CONCURRENT_CONNECTIONS', 50))
    
    # Stricter rate limiting
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', 30))
    RATE_LIMIT_BURST = int(os.getenv('RATE_LIMIT_BURST', 50))
    
    # Production security settings
    ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', '').split(',')
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    def __init__(self):
        super().__init__()
        required_vars = ['SECRET_KEY', 'JWT_SECRET_KEY', 'ALLOWED_ORIGINS']
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
        if '*' in self.ALLOWED_ORIGINS:
            raise ValueError("Wildcard CORS origin (*) is not allowed in production")


# Determine which configuration to use based on environment
env = os.getenv('FLASK_ENV', 'production').lower()

if env == 'development':
    config = DevelopmentConfig()
elif env == 'testing':
    config = TestingConfig()
else:
    config = ProductionConfig()
