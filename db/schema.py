"""
db/schema.py
SQLite schema definition, connection helper, and init_db() for Echo demo.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "echo.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    package TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL,
    first_patched_version TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS version_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT REFERENCES cves(cve_id),
    version_range TEXT NOT NULL,
    pivot_version TEXT NOT NULL,
    artifact_filename TEXT,
    artifact_sha256 TEXT,
    built_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS request_log (
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    last_requested TIMESTAMP NOT NULL,
    request_count INTEGER DEFAULT 1,
    PRIMARY KEY (package, version)
);
"""


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        conn.executescript(_SCHEMA)
