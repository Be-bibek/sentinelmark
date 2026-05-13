"""
app/db/session.py — Database Session Management

ARCHITECTURE RATIONALE
======================
FastAPI's dependency injection provides scoped database sessions. Each inbound
HTTP request receives its own SQLAlchemy session, isolated from concurrent requests.

This guarantees:
  - Forensic writes are atomic: either the full verdict is persisted or nothing is.
  - Partial writes cannot corrupt the audit ledger (rolled back on exception).
  - Sessions are always closed after the request lifetime, preventing connection leaks.

DATABASE CONFIGURATION:
  SQLite is used for MVP. The `check_same_thread=False` flag is required because
  FastAPI's async handlers run across a thread pool. SQLAlchemy's connection pool
  handles thread safety correctly when this flag is set.

PERFORMANCE TRADEOFFS:
  SQLite is appropriate for MVP due to its zero-administration requirements and
  adequate throughput for low-rate forensic logging (< 1000 events/s). For
  production-scale deployment, this module's DATABASE_URL and engine configuration
  would be replaced with PostgreSQL (asyncpg) without changing any calling code.
"""

import os
from typing import AsyncGenerator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session

from app.db.models import Base

# Database file is stored in the project root data directory.
DB_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")
os.makedirs(DB_DIR, exist_ok=True)
DATABASE_URL = f"sqlite:///{os.path.join(DB_DIR, 'sentinelmark.db')}"

# Create synchronous engine (FastAPI handles async via thread pool for sync ORM ops).
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,  # Set True for SQL query debugging
)

# Enable WAL mode for SQLite: allows concurrent reads during writes.
# Critical for forensic workloads where analysis queries run alongside ingestion.
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

# Session factory — bound to the engine above
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """
    Create all database tables if they don't exist.
    Called once at application startup.
    """
    Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    """
    FastAPI dependency: yield a scoped database session per request.
    
    Usage:
        @app.post("/ingest")
        async def ingest(event: TelemetryEvent, db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
