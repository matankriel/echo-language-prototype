"""
db/seed.py
Seeds the Echo demo database with 2 CVEs, version groups, and demo request_log rows.

Run from project root:
    python3 db/seed.py
"""

import hashlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from db.schema import get_connection, init_db

ARTIFACTS_DIR = Path(__file__).parent.parent / "factory" / "artifacts"

_G = "\033[0;32m"
_Y = "\033[1;33m"
_C = "\033[0;36m"
_B = "\033[1m"
_X = "\033[0m"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def now_minus(days: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def seed() -> None:
    init_db()

    with get_connection() as conn:
        # ── Wipe existing data ──────────────────────────────────────────────────
        conn.execute("DELETE FROM request_log")
        conn.execute("DELETE FROM version_groups")
        conn.execute("DELETE FROM cves")

        # ── CVEs ───────────────────────────────────────────────────────────────
        conn.execute(
            """
            INSERT INTO cves (cve_id, package, severity, cvss_score, first_patched_version, description)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "CVE-2021-33503",
                "urllib3",
                "High",
                7.5,
                "1.26.5",
                "ReDoS via crafted HTTP response header in urllib3.util.url",
            ),
        )

        conn.execute(
            """
            INSERT INTO cves (cve_id, package, severity, cvss_score, first_patched_version, description)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "CVE-2023-32681",
                "requests",
                "Medium",
                6.1,
                "2.31.0",
                "SSRF via trusted Host header being forwarded through redirects to untrusted origins",
            ),
        )

        # ── version_groups for CVE-2021-33503 (urllib3) ────────────────────────
        urllib3_groups = [
            (">=1.25.4,<1.25.8", "1.25.7", "urllib3-1.25.7+echo1-py2.py3-none-any.whl"),
            (">=1.25.8,<1.26.5", "1.26.4", "urllib3-1.26.4+echo1-py2.py3-none-any.whl"),
            (">=2.0.0,<2.0.6",   "2.0.5",  "urllib3-2.0.5+echo1-py3-none-any.whl"),
        ]

        for version_range, pivot, filename in urllib3_groups:
            whl_path = ARTIFACTS_DIR / filename
            if whl_path.exists():
                sha256 = sha256_of(whl_path)
                built_at = now_minus(0)
            else:
                sha256 = None
                built_at = None

            conn.execute(
                """
                INSERT INTO version_groups (cve_id, version_range, pivot_version, artifact_filename, artifact_sha256, built_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                ("CVE-2021-33503", version_range, pivot, filename if whl_path.exists() else None, sha256, built_at),
            )

        # ── version_groups for CVE-2023-32681 (requests) ───────────────────────
        conn.execute(
            """
            INSERT INTO version_groups (cve_id, version_range, pivot_version, artifact_filename, artifact_sha256, built_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("CVE-2023-32681", ">=2.1.0,<2.31.0", "2.28.2", None, None, None),
        )

        # ── request_log (demo entries showing within/outside 30d contrast) ─────
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

    print(f"\n{_B}Echo DB seeded:{_X}")
    print(f"\n  {_B}CVEs:{_X}")

    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM cves").fetchall()
        print(f"  {'CVE ID':<20}  {'Package':<10}  {'Severity':<8}  {'CVSS':<5}  {'First Patched'}")
        print("  " + "─" * 65)
        for r in rows:
            sev_col = _Y if r["severity"] == "High" else _C
            print(f"  {r['cve_id']:<20}  {r['package']:<10}  {sev_col}{r['severity']:<8}{_X}  {r['cvss_score']:<5}  {r['first_patched_version']}")

        print(f"\n  {_B}Version groups:{_X}")
        vg_rows = conn.execute(
            """
            SELECT vg.id, vg.cve_id, vg.version_range, vg.pivot_version,
                   vg.artifact_filename, vg.built_at
            FROM version_groups vg
            ORDER BY vg.cve_id, vg.id
            """
        ).fetchall()
        print(f"  {'ID':<4}  {'CVE':<20}  {'Range':<22}  {'Pivot':<8}  {'Status'}")
        print("  " + "─" * 75)
        for r in vg_rows:
            status = f"{_G}pre-built{_X}" if r["artifact_filename"] else f"{_Y}not built{_X}"
            print(f"  {r['id']:<4}  {r['cve_id']:<20}  {r['version_range']:<22}  {r['pivot_version']:<8}  {status}")

        print(f"\n  {_B}Request log:{_X}")
        rl_rows = conn.execute("SELECT * FROM request_log ORDER BY package, version").fetchall()
        print(f"  {'Package':<10}  {'Version':<10}  {'Last Requested':<22}  {'Count':<6}  {'30d window'}")
        print("  " + "─" * 72)
        from datetime import datetime, timedelta, timezone
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        for r in rl_rows:
            lr = datetime.fromisoformat(r["last_requested"].replace("Z", "+00:00"))
            if lr.tzinfo is None:
                lr = lr.replace(tzinfo=timezone.utc)
            within = lr > cutoff
            w_label = f"{_G}WITHIN{_X}" if within else f"{_Y}OUTSIDE{_X}"
            print(f"  {r['package']:<10}  {r['version']:<10}  {r['last_requested']:<22}  {r['request_count']:<6}  {w_label}")

    print()


if __name__ == "__main__":
    seed()
