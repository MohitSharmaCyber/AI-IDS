"""
logger.py

Centralized logging configuration for the Packet Capture module.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from pathlib import Path
import logging
from logging.handlers import RotatingFileHandler

# -------------------------------------------------------
# Create logs directory if it doesn't exist
# -------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

LOG_DIR = PROJECT_ROOT / "logs"

LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "packet_capture.log"

# -------------------------------------------------------
# Logger Configuration
# -------------------------------------------------------

LOGGER_NAME = "packet_capture"

logger = logging.getLogger(LOGGER_NAME)

logger.setLevel(logging.DEBUG)

# Prevent duplicate logs
logger.propagate = False

# -------------------------------------------------------
# Formatter
# -------------------------------------------------------

formatter = logging.Formatter(
    fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# -------------------------------------------------------
# Console Handler
# -------------------------------------------------------

console_handler = logging.StreamHandler()

console_handler.setLevel(logging.INFO)

console_handler.setFormatter(formatter)

# -------------------------------------------------------
# File Handler
# -------------------------------------------------------

file_handler = RotatingFileHandler(
    filename=LOG_FILE,
    maxBytes=5 * 1024 * 1024,
    backupCount=5,
    encoding="utf-8",
)

file_handler.setLevel(logging.DEBUG)

file_handler.setFormatter(formatter)

# -------------------------------------------------------
# Avoid duplicate handlers
# -------------------------------------------------------

if not logger.handlers:

    logger.addHandler(console_handler)

    logger.addHandler(file_handler)

# -------------------------------------------------------
# Startup Message
# -------------------------------------------------------

logger.info("Packet Capture Logger Initialized")