"""
app/logging/config.py — Structured Logging Configuration

Uses Python's standard logging library with a structured format suitable for
forensic analysis tooling. All security events (tamper, replay, anomaly)
are logged with consistent structured fields for downstream SIEM ingestion.
"""

import logging
import os

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "sentinel_cloud.log")


def configure_logging() -> None:
    """Configure structured logging for the SentinelMark verifier service."""
    fmt = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )
    # Quiet noisy SQLAlchemy engine logs unless debugging
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
