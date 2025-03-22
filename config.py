import os

# Simple function to load environment variables from .env file
def load_env_from_file():
    """Load environment variables from .env file if it exists"""
    try:
        if os.path.exists('.env'):
            with open('.env', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip()
    except Exception as e:
        print(f"Warning: Could not load .env file: {e}")

# Try to load environment variables from .env file
load_env_from_file()

class Config:
    """Configuration settings for the application."""
    
    # MongoDB Configuration
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb+srv://infoziantappwrite:infoziant%4002@cluster0.kt0ru.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
    MONGO_DB_NAME = os.getenv('MONGO_DB_NAME', 'test')
    MONGO_SCAN_COLLECTION = os.getenv('MONGO_SCAN_COLLECTION', 'scan')
    MONGO_USER_COLLECTION = os.getenv('MONGO_USER_COLLECTION', 'users')
    
    # API Configuration
    API_PORT = int(os.getenv('API_PORT', 5000))
    API_HOST = os.getenv('API_HOST', '0.0.0.0')
    DEBUG_MODE = os.getenv('DEBUG_MODE', 'False').lower() == 'true'
    
    # Scanning Configuration
    SCAN_TIMEOUT = int(os.getenv('SCAN_TIMEOUT', 300))  # Default timeout in seconds
    MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', 10))
    RESULTS_DIR = os.getenv('RESULTS_DIR', 'results')
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = os.getenv('LOG_FORMAT', '%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    LOG_FILE = os.getenv('LOG_FILE', 'security_api.log')
    
    # Scanner-specific Configuration
    SQLMAP_ARGS = os.getenv('SQLMAP_ARGS', '--batch --random-agent')
    DALFOX_ARGS = os.getenv('DALFOX_ARGS', '--silence --skip-bav')
    
    # Security Configuration
    ENABLE_AUTH = os.getenv('ENABLE_AUTH', 'True').lower() == 'true'
    
    # Performance Configuration
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', 10))
    MAX_CONNECTIONS = int(os.getenv('MAX_CONNECTIONS', 100))
    NUM_WORKERS = int(os.getenv('NUM_WORKERS', 4))
    
    # Feature Flags
    ENABLE_NMAP = os.getenv('ENABLE_NMAP', 'True').lower() == 'true'
    ENABLE_SUBDOMAIN_SCAN = os.getenv('ENABLE_SUBDOMAIN_SCAN', 'True').lower() == 'true'
    ENABLE_VULNERABILITY_SCAN = os.getenv('ENABLE_VULNERABILITY_SCAN', 'True').lower() == 'true'
    
    # Timezone Configuration
    SERVER_TIMEZONE = os.getenv('SERVER_TIMEZONE', 'US/Pacific')
    OUTPUT_TIMEZONE = os.getenv('OUTPUT_TIMEZONE', 'Asia/Kolkata')

# Create configuration instance
config = Config()
