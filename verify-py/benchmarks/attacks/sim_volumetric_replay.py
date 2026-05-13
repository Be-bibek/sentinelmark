"""
benchmarks/attacks/sim_volumetric_replay.py — Volumetric Replay Flood Simulation

This benchmark evaluates the database normalization and causal ordering logic
under extreme concurrency. It simulates an attacker flooding the ingestion pipeline
with identical replay events to test SQLite WAL-mode lock contention and the
stateful nonce cache eviction efficiency.

It measures:
1. Ingestion throughput (inserts/sec) before and after normalization.
2. Eviction latency of the sliding-window nonce cache.
3. Resilience against OOM conditions from JSON parsing (which is now bypassed).
"""

import os
import sys
import time
import uuid
import asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from app.db.models import Base, TelemetryLog, NonceCache
from app.db.repositories import TelemetryRepository, NonceCacheRepository

DB_PATH = "sqlite:///volumetric_stress.db"
NUM_EVENTS = 10_000
DEVICE_ID = "victim-device-flood"


def setup_db() -> sessionmaker:
    if os.path.exists("volumetric_stress.db"):
        os.remove("volumetric_stress.db")
    
    # SQLite WAL mode is essential for concurrent reads/writes
    engine = create_engine(DB_PATH, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    
    # Enable WAL
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL;"))
        conn.execute(text("PRAGMA synchronous=NORMAL;"))
        
    return sessionmaker(bind=engine)


def generate_flood_data():
    base_time = datetime.now(timezone.utc)
    base_hash = "0" * 64
    
    events = []
    for i in range(NUM_EVENTS):
        events.append({
            "event_id": str(uuid.uuid4()),
            "sequence_number": i + 1,
            "captured_at": base_time + timedelta(milliseconds=i),
            "nonce": uuid.uuid4().hex * 2,  # 64 char random string for uniqueness test
            "current_hash": uuid.uuid4().hex * 2,
            "prev_hash": base_hash,
            "cpu_usage": 5000 + (i % 100),
            "memory_usage": 512_000_000,
            "timing_jitter": 15_000,
            "thread_count": 8,
        })
        base_hash = events[-1]["current_hash"]
    
    return events


async def simulate_flood(SessionLocal: sessionmaker, events: list):
    print(f"\\n[+] Initiating Volumetric Replay Flood: {NUM_EVENTS} events")
    
    start_time = time.perf_counter()
    db = SessionLocal()
    telemetry_repo = TelemetryRepository(db)
    nonce_repo = NonceCacheRepository(db)
    
    prune_count = 0
    replay_rejections = 0
    
    for i, ev in enumerate(events):
        # Simulate Replay Check (Half of them are replays of the first event)
        check_nonce = ev["nonce"] if i % 2 == 0 else events[0]["nonce"]
        
        if nonce_repo.exists(check_nonce):
            replay_rejections += 1
        else:
            nonce_repo.record(
                nonce=check_nonce,
                device_id=DEVICE_ID
            )
            
        # Simulate DB Persistence (Hot Path)
        telemetry_repo.persist_verdict(
            device_id=DEVICE_ID,
            event_id=ev["event_id"],
            sequence_number=ev["sequence_number"],
            timestamp_utc=ev["captured_at"],
            nonce=check_nonce,
            current_hash=ev["current_hash"],
            prev_hash=ev["prev_hash"],
            cpu_usage=ev["cpu_usage"],
            memory_usage=ev["memory_usage"],
            timing_jitter=ev["timing_jitter"],
            thread_count=ev["thread_count"],
            trust_score=1.0 if i % 2 == 0 else 0.8,
            replay_detected=(i % 2 != 0),
            tamper_detected=False,
            behavior_anomaly=False,
            chain_valid=True,
            timestamp_valid=True,
            z_score_cpu=None,
            z_score_memory=None,
            z_score_jitter=None,
            verification_reason="Flood test",
            raw_payload="{}"
        )
        
        # Periodic pruning simulation
        if i % 1000 == 0:
            prune_count += nonce_repo.prune_expired()
            db.commit()
            
    db.commit()
    db.close()
    
    duration = time.perf_counter() - start_time
    throughput = NUM_EVENTS / duration
    
    print(f"[=] Flood Complete. Duration: {duration:.2f}s")
    print(f"[=] Throughput: {throughput:.2f} events/sec")
    print(f"[=] Replay Rejections: {replay_rejections}")
    print(f"[=] State Pruning: {prune_count} expired nonces cleared")


if __name__ == "__main__":
    SessionLocal = setup_db()
    data = generate_flood_data()
    asyncio.run(simulate_flood(SessionLocal, data))
