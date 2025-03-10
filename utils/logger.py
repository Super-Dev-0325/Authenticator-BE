import logging
import sys
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

def log_info(message: str):
    """Log info message"""
    logger.info(message)

def log_error(message: str, error: Exception = None):
    """Log error message"""
    if error:
        logger.error(f"{message}: {str(error)}", exc_info=True)
    else:
        logger.error(message)

def log_warning(message: str):
    """Log warning message"""
    logger.warning(message)

