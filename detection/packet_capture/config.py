"""
config.py

Configuration management for the Packet Capture module.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv
import os

# ---------------------------------------------------
# Load Environment Variables
# ---------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(PROJECT_ROOT / ".env")


@dataclass(frozen=True)
class Config:
    """
    Centralized configuration for AI-IDS.
    """

    APP_NAME: str = os.getenv("APP_NAME", "AI-IDS")

    APP_VERSION: str = os.getenv("APP_VERSION", "1.0.0")

    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    NETWORK_INTERFACE: str = os.getenv("NETWORK_INTERFACE", "Wi-Fi")

    CAPTURE_TIMEOUT: int = int(os.getenv("CAPTURE_TIMEOUT", 30))

    PACKET_LIMIT: int = int(os.getenv("PACKET_LIMIT", 0))

    PROMISCUOUS_MODE: bool = (
        os.getenv("PROMISCUOUS_MODE", "True").lower() == "true"
    )

    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///database/ai_ids.db",
    )


config = Config()