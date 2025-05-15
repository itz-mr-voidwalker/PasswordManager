"""
Environment Handler Module for the Auth Package

This module is responsible for loading and providing access to environment variables
defined in the .env file located at the project root.

Author: [Your Name]
Date: [Date]
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Resolve the absolute path to the project root (one level up from this file)
ROOT_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT_DIR / ".env"

# Load the .env file
load_dotenv(dotenv_path=ENV_PATH)


def get_env_var(key: str, default: str = None) -> str:
    """
    Retrieve an environment variable with an optional default.

    Args:
        key (str): The name of the environment variable.
        default (str, optional): The fallback value if the variable is not found.

    Returns:
        str: The value of the environment variable or the default.
    """
    return os.getenv(key, default)
