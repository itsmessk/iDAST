import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class BaseConfig:
    """Base configuration settings for the application."""
    
    # MongoDB Configuration
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
    MONGO_DB_NAME = os.getenv('MONGO_DB_NAME', 'secpro')
    MONGO_SCAN_COLLECTION = os.getenv('MONGO_SCAN_COLLECTION', 'scan')
    MONGO_USER_COLLECTION = os.getenv('MONGO_USER_COLLECTION', 'users')
    
    # API Configuration
    API_PORT = int(os.getenv('PORT', 3000))
    API_HOST = os.getenv('API_HOST', '0.0.0.0')
    DEBUG_MODE = False
    
    # Scanning Configuration
    SCAN_TIMEOUT = int(os.getenv('SCAN_TIMEOUT', 300))  # Default timeout in seconds
    MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', 10))
    RESULTS_DIR = os.getenv('RESULTS_DIR', 'results')
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = os.getenv('LOG_FORMAT', '%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    LOG_FILE = os.getenv('LOG_FILE', 'logs/security_api.log')
    
    # Scanner-specific Configuration
    SQLMAP_ARGS = os.getenv('SQLMAP_ARGS', '--batch --random-agent')
    DALFOX_ARGS = os.getenv('DALFOX_ARGS', '--silence --skip-bav')
    
    # Security Configuration
    ENABLE_AUTH = True
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(24).hex())
    
    # Performance Configuration
    WORKER_PROCESSES = int(os.getenv('WORKER_PROCESSES', 4))
    WORKER_THREADS = int(os.getenv('WORKER_THREADS', 2))
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', 120))
    
    # Rate Limiting
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', 60))


class DevelopmentConfig(BaseConfig):
    """Development configuration settings."""
    DEBUG_MODE = True
    ENABLE_AUTH = os.getenv('ENABLE_AUTH', 'True').lower() == 'true'
    RATE_LIMIT_ENABLED = False


class TestingConfig(BaseConfig):
    """Testing configuration settings."""
    DEBUG_MODE = True
    MONGO_DB_NAME = 'secpro_test'
    RESULTS_DIR = 'tests/scan_results'
    LOG_FILE = 'tests/logs/security_api.log'
    ENABLE_AUTH = False
    RATE_LIMIT_ENABLED = False


class ProductionConfig(BaseConfig):
    """Production configuration settings."""
    # Ensure all security features are enabled
    DEBUG_MODE = False
    ENABLE_AUTH = True
    
    # More conservative resource usage
    MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', 5))
    
    # Stricter rate limiting
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', 30))
    
    # Ensure secret key is set
    def __init__(self):
        if os.getenv('SECRET_KEY') is None:
            raise ValueError("SECRET_KEY environment variable must be set in production")


# Determine which configuration to use based on environment
env = os.getenv('FLASK_ENV', 'production').lower()

if env == 'development':
    config = DevelopmentConfig()
elif env == 'testing':
    config = TestingConfig()
else:
    config = ProductionConfig()
