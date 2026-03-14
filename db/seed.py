"""
db/seed.py
Seeds the Echo demo database with synthetic request_log rows that illustrate
the 30-day demand window used by the builder.

CVE and version_group data is now populated by db/discover.py.

Run from project root:
    python3 db/seed.py
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from db.schema import get_connection, init_db

_G = "\033[0;32m"
_Y = "\033[1;33m"
_C = "\033[0;36m"
_B = "\033[1m"
_X = "\033[0m"


def now_minus(days: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def seed() -> None:
    init_db()

    with get_connection() as conn:
        conn.execute("DELETE FROM request_log")

        request_log_rows = [
            ("urllib3",  "1.26.0", now_minus(15), 3),   # within 30d → eligible
            ("urllib3",  "2.3.0",  now_minus(5),  1),   # within 30d but not in CVE range
            ("urllib3",  "1.25.3", now_minus(45), 2),   # outside 30d → skip
            ("requests", "2.28.0", now_minus(7),  5),   # within 30d → eligible
            ("requests", "2.26.0", now_minus(50), 1),   # outside 30d → skip
        ]

        conn.executemany(
            """
            INSERT INTO request_log (package, version, last_requested, request_count)
            VALUES (?, ?, ?, ?)
            """,
            request_log_rows,
        )

    print(f"\n{_B}Request log seeded:{_X}")
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM request_log ORDER BY package, version").fetchall()
        print(f"  {'Package':<10}  {'Version':<10}  {'Last Requested':<22}  {'Count':<6}  {'30d window'}")
        print("  " + "─" * 72)
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        for r in rows:
            lr = datetime.fromisoformat(r["last_requested"].replace("Z", "+00:00"))
            if lr.tzinfo is None:
                lr = lr.replace(tzinfo=timezone.utc)
            within = lr > cutoff
            w_label = f"{_G}WITHIN{_X}" if within else f"{_Y}OUTSIDE{_X}"
            print(f"  {r['package']:<10}  {r['version']:<10}  {r['last_requested']:<22}  {r['request_count']:<6}  {w_label}")
    print()


if __name__ == "__main__":
    seed()
