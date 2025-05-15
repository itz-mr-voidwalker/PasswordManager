"""
Custom Logging Setup Module

Provides a configurable logging utility class that sets up a console and file logger
with a unified formatter.

Author: [Sai Vignesh]
Date: [14/05/2025]
"""

import logging

def setup_logging():
        """
        Initialize the logger with the given name, log file, and logging level.

        Args:
            Static Method, No Args
        """
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/app.logs', mode='a')
            ]
        )
        return logging.getLogger(__name__)