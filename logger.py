import logging
import os
from logging.handlers import RotatingFileHandler
from config import config

class Logger:
    """Centralized logging configuration for the application."""
    
    def __init__(self):
        """Initialize the logger with configuration from config."""
        self.log_level = self._get_log_level()
        self.log_format = config.LOG_FORMAT
        self.log_file = config.LOG_FILE
        
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        log_file_path = os.path.join('logs', self.log_file)
        
        # Configure root logger
        logging.basicConfig(
            level=self.log_level,
            format=self.log_format,
            handlers=[
                # Console handler
                logging.StreamHandler(),
                # File handler with rotation (10MB max size, keep 5 backup files)
                RotatingFileHandler(
                    log_file_path, 
                    maxBytes=10*1024*1024,  # 10MB
                    backupCount=5
                )
            ]
        )
        
        # Create a logger instance
        self.logger = logging.getLogger('security_api')
        self.logger.setLevel(self.log_level)
        
        self.logger.info(f"Logger initialized with level: {self.log_level}")
    
    def _get_log_level(self):
        """Convert string log level to logging constant."""
        levels = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        return levels.get(config.LOG_LEVEL.upper(), logging.INFO)
    
    def get_logger(self, name=None):
        """Get a logger instance with optional name."""
        if name:
            return logging.getLogger(f'security_api.{name}')
        return self.logger

# Create a global logger instance
logger_instance = Logger()
get_logger = logger_instance.get_logger
