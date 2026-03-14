"""
registry/server.py
PEP 503-compatible private package registry + CVE check endpoint.

Start with:
    uvicorn registry.server:app --port 8000
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse
from packaging.specifiers import SpecifierSet
from packaging.version import Version

sys.path.insert(0, str(Path(__file__).parent.parent))
from db.schema import get_connection, init_db

ARTIFACTS_DIR = Path(__file__).parent.parent / "factory" / "artifacts"

app = FastAPI(title="Echo Registry")


@app.on_event("startup")
def startup() -> None:
    init_db()


# ── PEP 503 Simple Index ───────────────────────────────────────────────────────

@app.get("/simple/", response_class=HTMLResponse)
def simple_root() -> str:
    with get_connection() as conn:
        packages = conn.execute(
            "SELECT DISTINCT package FROM cves WHERE cve_id IN "
            "(SELECT DISTINCT cve_id FROM version_groups WHERE artifact_filename IS NOT NULL)"
        ).fetchall()

    links = "\n".join(
        f'    <a href="/simple/{r["package"]}/">{r["package"]}</a>'
        for r in packages
    )
    return f"""<!DOCTYPE html>
<html>
<head><title>Echo Simple Index</title></head>
<body>
  <h1>Echo Simple Index</h1>
{links}
</body>
</html>
"""


@app.get("/simple/{package}/", response_class=HTMLResponse)
def simple_package(package: str) -> str:
    with get_connection() as conn:
        groups = conn.execute(
            """
            SELECT vg.artifact_filename, vg.artifact_sha256,
                   vg.version_range, vg.pivot_version,
                   c.cve_id, c.severity, c.cvss_score, c.first_patched_version
            FROM version_groups vg
            JOIN cves c ON c.cve_id = vg.cve_id
            WHERE c.package = ? AND vg.artifact_filename IS NOT NULL
            ORDER BY vg.id
            """,
            (package.lower(),),
        ).fetchall()

    items = []
    for g in groups:
        sha = g["artifact_sha256"] or ""
        href = f'/files/{g["artifact_filename"]}' + (f"#sha256={sha}" if sha else "")
        comment = (
            f"<!-- echo:cve_id={g['cve_id']} severity={g['severity']} "
            f"cvss={g['cvss_score']}\n"
            f"     first_patched={g['first_patched_version']} "
            f"version_range={g['version_range']} pivot={g['pivot_version']} -->"
        )
        items.append(
            f"    {comment}\n"
            f'    <a href="{href}">{g["artifact_filename"]}</a>'
        )

    links = "\n".join(items)
    return f"""<!DOCTYPE html>
<html>
<head><title>Echo: {package}</title></head>
<body>
  <h1>Links for {package}</h1>
{links}
</body>
</html>
"""


# ── File serving ───────────────────────────────────────────────────────────────

@app.get("/files/{filename}")
def serve_file(filename: str) -> FileResponse:
    path = ARTIFACTS_DIR / filename
    if not path.exists():
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"{filename} not found")
    return FileResponse(path)


# ── CVE check + request_log upsert ────────────────────────────────────────────

@app.get("/check/{package}/{version}")
def check(package: str, version: str) -> dict:
    # Echo-patched builds are always safe
    if "+echo1" in version:
        return {"vulnerable": False}

    # Upsert request_log
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO request_log (package, version, last_requested, request_count)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(package, version) DO UPDATE SET
                last_requested = excluded.last_requested,
                request_count  = request_count + 1
            """,
            (package.lower(), version, now_str),
        )

    # Check vulnerability
    try:
        req_ver = Version(version)
    except Exception:
        return {"vulnerable": False}

    with get_connection() as conn:
        groups = conn.execute(
            """
            SELECT vg.id, vg.version_range, vg.pivot_version, vg.artifact_filename,
                   c.cve_id, c.severity, c.cvss_score, c.first_patched_version, c.description
            FROM version_groups vg
            JOIN cves c ON c.cve_id = vg.cve_id
            WHERE c.package = ?
            ORDER BY c.cvss_score DESC, vg.id
            """,
            (package.lower(),),
        ).fetchall()

    for g in groups:
        try:
            spec = SpecifierSet(g["version_range"])
        except Exception:
            continue
        if req_ver in spec:
            fp = g["first_patched_version"]
            return {
                "vulnerable": True,
                "cve_id": g["cve_id"],
                "severity": g["severity"],
                "cvss_score": g["cvss_score"],
                "first_patched_version": fp,
                "patched_artifact": g["artifact_filename"],
                "official_fix": f"Upgrade to {package}>={fp} (pip install '{package}>={fp}')",
                "version_range": g["version_range"],
                "description": g["description"],
            }

    return {"vulnerable": False}
