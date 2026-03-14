"""
db/discover.py
Queries the GitHub Security Advisory database (GHSA) for a given list of pip
packages and upserts the results into the Echo SQLite database.

Usage:
    export GITHUB_TOKEN=ghp_xxx
    python3 db/discover.py urllib3 requests

Requires:
    - GITHUB_TOKEN env var (any token with public read access)
    - packaging library (installed in .venv)
"""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from db.schema import get_connection, init_db

ARTIFACTS_DIR = Path(__file__).parent.parent / "factory" / "artifacts"


def _ssl_context() -> ssl.SSLContext:
    """Return an SSL context using certifi's CA bundle when available."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()

_G = "\033[0;32m"
_Y = "\033[1;33m"
_C = "\033[0;36m"
_R = "\033[0;31m"
_B = "\033[1m"
_X = "\033[0m"

GHSA_API = "https://api.github.com/graphql"
PYPI_API = "https://pypi.org/pypi/{package}/json"

_SEVERITY_MAP = {
    "LOW": "Low",
    "MODERATE": "Medium",
    "HIGH": "High",
    "CRITICAL": "Critical",
}

_QUERY = """
query($pkg: String!, $cursor: String) {
  securityVulnerabilities(ecosystem: PIP, package: $pkg, first: 100, after: $cursor) {
    pageInfo { hasNextPage endCursor }
    nodes {
      advisory {
        ghsaId
        summary
        severity
        cvss { score }
        identifiers { type value }
        publishedAt
        withdrawnAt
      }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
      package { name }
    }
  }
}
"""


def query_ghsa(package: str, token: str) -> list[dict]:
    """Return all vulnerability nodes for a package from GHSA (paginated)."""
    nodes: list[dict] = []
    cursor = None

    while True:
        variables: dict = {"pkg": package, "cursor": cursor}
        payload = json.dumps({"query": _QUERY, "variables": variables}).encode()

        req = urllib.request.Request(
            GHSA_API,
            data=payload,
            headers={
                "Authorization": f"bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, context=_ssl_context()) as resp:
            data = json.loads(resp.read())

        if "errors" in data:
            raise RuntimeError(f"GHSA API error: {data['errors']}")

        vuln_data = data["data"]["securityVulnerabilities"]
        nodes.extend(vuln_data["nodes"])

        page_info = vuln_data["pageInfo"]
        if not page_info["hasNextPage"]:
            break
        cursor = page_info["endCursor"]

    return nodes


def resolve_pivot(package: str, version_range: str) -> str | None:
    """
    Query PyPI for all published versions of package; return the latest stable
    version that falls inside version_range. Returns None if none found.
    """
    url = PYPI_API.format(package=package)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, context=_ssl_context()) as resp:
            data = json.loads(resp.read())
    except Exception as exc:
        print(f"  {_Y}Warning: PyPI lookup failed for {package}: {exc}{_X}", file=sys.stderr)
        return None

    try:
        spec = SpecifierSet(version_range)
    except Exception as exc:
        print(f"  {_Y}Warning: invalid version range '{version_range}': {exc}{_X}", file=sys.stderr)
        return None

    candidates: list[Version] = []
    for ver_str in data.get("releases", {}):
        try:
            v = Version(ver_str)
        except InvalidVersion:
            continue
        if v.is_prerelease or v.is_devrelease:
            continue
        if v in spec:
            candidates.append(v)

    if not candidates:
        return None

    return str(max(candidates))


def advisory_to_rows(node: dict) -> tuple[dict | None, list[dict]]:
    """
    Map a GHSA vulnerability node to (cve_row, [vg_row]).
    Returns (None, []) if the advisory is withdrawn or has no version range.
    """
    advisory = node["advisory"]

    if advisory.get("withdrawnAt"):
        return None, []

    version_range = node.get("vulnerableVersionRange")
    if not version_range:
        return None, []

    # Normalise spacing: ">= 2.1.0, < 2.31.0" → ">=2.1.0,<2.31.0"
    version_range = ",".join(
        part.strip().replace(" ", "") for part in version_range.split(",")
    )

    # CVE ID: prefer CVE identifier, fall back to GHSA ID
    cve_id = advisory["ghsaId"]
    for ident in advisory.get("identifiers", []):
        if ident["type"] == "CVE":
            cve_id = ident["value"]
            break

    raw_severity = advisory.get("severity", "MODERATE")
    severity = _SEVERITY_MAP.get(raw_severity, "Medium")

    cvss = advisory.get("cvss") or {}
    cvss_score = cvss.get("score")

    fpv = node.get("firstPatchedVersion")
    first_patched_version = fpv["identifier"] if fpv else None

    package_name = node["package"]["name"].lower()
    description = advisory.get("summary", "")

    cve_row = {
        "cve_id": cve_id,
        "package": package_name,
        "severity": severity,
        "cvss_score": cvss_score,
        "first_patched_version": first_patched_version,
        "description": description,
    }

    vg_row = {
        "cve_id": cve_id,
        "version_range": version_range,
        "pivot_version": None,  # filled in by main() after PyPI lookup
    }

    return cve_row, [vg_row]


def upsert_cve(conn, row: dict) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO cves
            (cve_id, package, severity, cvss_score, first_patched_version, description)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            row["cve_id"],
            row["package"],
            row["severity"],
            row["cvss_score"],
            row["first_patched_version"],
            row["description"],
        ),
    )


def upsert_version_group(conn, row: dict) -> None:
    """
    INSERT OR IGNORE preserves any existing row that already has an
    artifact_filename/sha256 set by the builder — discovered data populates
    but built artifacts are never overwritten.
    """
    conn.execute(
        """
        INSERT OR IGNORE INTO version_groups
            (cve_id, version_range, pivot_version)
        VALUES (?, ?, ?)
        """,
        (row["cve_id"], row["version_range"], row["pivot_version"]),
    )


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def link_prebuilt_artifacts() -> None:
    """
    Scan factory/artifacts/ for *+echo1*.whl files and link them to any
    version_group row whose (package, pivot_version) matches — preserving
    the pre-built urllib3 wheels across discover runs that wipe the DB.
    """
    if not ARTIFACTS_DIR.exists():
        return

    built_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    with get_connection() as conn:
        for whl_path in sorted(ARTIFACTS_DIR.glob("*+echo1*.whl")):
            # Wheel filename: {dist}-{version}-{python}-{abi}-{platform}.whl
            parts = whl_path.name.split("-")
            if len(parts) < 2:
                continue
            package = parts[0]
            raw_version = parts[1]               # e.g. "1.26.4+echo1"
            pivot = raw_version.replace("+echo1", "")

            rows = conn.execute(
                """
                SELECT vg.id FROM version_groups vg
                JOIN cves c ON c.cve_id = vg.cve_id
                WHERE c.package = ? AND vg.pivot_version = ?
                  AND vg.artifact_filename IS NULL
                """,
                (package, pivot),
            ).fetchall()

            if rows:
                sha256 = sha256_of(whl_path)
                for row in rows:
                    conn.execute(
                        """
                        UPDATE version_groups
                        SET artifact_filename = ?, artifact_sha256 = ?, built_at = ?
                        WHERE id = ?
                        """,
                        (whl_path.name, sha256, built_at, row["id"]),
                    )
                print(f"  {_G}Linked pre-built:{_X} {whl_path.name}")


def print_db_tables() -> None:
    with get_connection() as conn:
        cve_rows = conn.execute("SELECT * FROM cves").fetchall()
        print(f"\n  {_B}CVEs:{_X}")
        print(f"  {'CVE / GHSA ID':<24}  {'Package':<10}  {'Severity':<8}  {'CVSS':<5}  {'First Patched'}")
        print("  " + "─" * 70)
        for r in cve_rows:
            sev_col = _Y if r["severity"] in ("High", "Critical") else _C
            cvss = f"{r['cvss_score']:.1f}" if r["cvss_score"] is not None else "—"
            fp = r["first_patched_version"] or "—"
            print(f"  {r['cve_id']:<24}  {r['package']:<10}  {sev_col}{r['severity']:<8}{_X}  {cvss:<5}  {fp}")

        vg_rows = conn.execute(
            """
            SELECT vg.id, vg.cve_id, vg.version_range, vg.pivot_version,
                   vg.artifact_filename
            FROM version_groups vg
            ORDER BY vg.cve_id, vg.id
            """
        ).fetchall()
        print(f"\n  {_B}Version groups:{_X}")
        print(f"  {'ID':<4}  {'CVE / GHSA ID':<24}  {'Range':<26}  {'Pivot':<12}  {'Status'}")
        print("  " + "─" * 82)
        for r in vg_rows:
            status = f"{_G}pre-built{_X}" if r["artifact_filename"] else f"{_Y}not built{_X}"
            pivot = r["pivot_version"] or "—"
            print(f"  {r['id']:<4}  {r['cve_id']:<24}  {r['version_range']:<26}  {pivot:<12}  {status}")


def main(targets: list[tuple[str, str | None]], token: str) -> None:
    """
    targets: list of (package, cve_filter_or_None).
    When cve_filter is set, only that specific CVE ID is stored for the package.
    """
    init_db()

    # Wipe CVE + version_group tables so each discovery run starts clean.
    # request_log is intentionally left intact (managed by seed.py).
    with get_connection() as conn:
        conn.execute("DELETE FROM version_groups")
        conn.execute("DELETE FROM cves")

    print(f"\n{_B}Echo — GitHub Security Advisory Discovery{_X}")

    for pkg, cve_filter in targets:
        filter_label = f" (filter: {cve_filter})" if cve_filter else ""
        print(f"\n  {_C}Querying GHSA for {pkg}{filter_label}...{_X}")
        try:
            nodes = query_ghsa(pkg, token)
        except Exception as exc:
            print(f"  {_R}Error: GHSA query failed for {pkg}: {exc}{_X}", file=sys.stderr)
            continue

        active = [n for n in nodes if not n["advisory"].get("withdrawnAt")]
        print(f"  Found {len(nodes)} node(s), {len(active)} active")

        for node in active:
            cve_row, vg_rows = advisory_to_rows(node)
            if cve_row is None:
                continue

            # Apply CVE filter when specified
            if cve_filter and cve_row["cve_id"] != cve_filter:
                continue

            for vg in vg_rows:
                pivot = resolve_pivot(pkg, vg["version_range"])
                if pivot is None:
                    print(
                        f"  {_Y}Warning: no pivot resolved for "
                        f"{pkg} {vg['version_range']} — skipping{_X}",
                        file=sys.stderr,
                    )
                    continue
                vg["pivot_version"] = pivot

                with get_connection() as conn:
                    upsert_cve(conn, cve_row)
                    upsert_version_group(conn, vg)

    link_prebuilt_artifacts()
    print_db_tables()
    print()


def _parse_targets(args: list[str]) -> list[tuple[str, str | None]]:
    """
    Parse CLI args into (package, cve_filter) pairs.
    Accepts:
        urllib3                    → ("urllib3", None)
        urllib3:CVE-2021-33503     → ("urllib3", "CVE-2021-33503")
    """
    targets = []
    for arg in args:
        if ":" in arg:
            pkg, cve = arg.split(":", 1)
            targets.append((pkg.strip(), cve.strip()))
        else:
            targets.append((arg.strip(), None))
    return targets


if __name__ == "__main__":
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        print(
            "Error: GITHUB_TOKEN is not set.\n"
            "Export it before running:  export GITHUB_TOKEN=ghp_xxx",
            file=sys.stderr,
        )
        sys.exit(1)

    raw_args = sys.argv[1:] if len(sys.argv) > 1 else ["urllib3", "requests"]
    main(_parse_targets(raw_args), token)
