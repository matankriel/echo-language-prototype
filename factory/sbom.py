"""
factory/sbom.py
CycloneDX 1.4 SBOM generator and wheel injector for Echo patched wheels.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def generate_sbom(
    package: str,
    pivot_version: str,
    first_patched: str,
    cve_id: str,
    severity: str,
    cvss: float,
    description: str,
) -> dict:
    patched_version = f"{pivot_version}+echo1"
    purl_patched = f"pkg:pypi/{package}@{patched_version}"
    purl_original = f"pkg:pypi/{package}@{pivot_version}"

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"vendor": "Echo", "name": "echo-patcher", "version": "1.0"}],
            "component": {
                "type": "library",
                "name": package,
                "version": patched_version,
                "purl": purl_patched,
            },
        },
        "components": [
            {
                "type": "library",
                "name": package,
                "version": pivot_version,
                "purl": purl_original,
                "evidence": {"licenses": []},
                "properties": [
                    {"name": "echo:original-version", "value": pivot_version},
                    {"name": "echo:patched-from-cve", "value": cve_id},
                    {"name": "echo:patch-strategy", "value": "backport"},
                ],
            }
        ],
        "vulnerabilities": [
            {
                "id": cve_id,
                "source": {
                    "name": "NVD",
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                },
                "ratings": [
                    {
                        "source": {"name": "NVD"},
                        "score": cvss,
                        "severity": severity.lower(),
                        "method": "CVSSv3",
                    }
                ],
                "description": description,
                "affects": [{"ref": purl_original}],
                "analysis": {
                    "state": "resolved",
                    "detail": "Backport patch applied. Wheel built by Echo patcher.",
                },
            }
        ],
    }


def _rewrite_zip_entry(whl_path: Path, entry_name: str, new_data: bytes) -> None:
    """Rewrite a single entry in a zip file by rebuilding the archive in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(whl_path, "r") as zf_in:
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf_out:
            for item in zf_in.infolist():
                if item.filename == entry_name:
                    zf_out.writestr(item, new_data)
                else:
                    zf_out.writestr(item, zf_in.read(item.filename))
    whl_path.write_bytes(buf.getvalue())


def inject_sbom_into_wheel(whl_path: Path, sbom: dict) -> None:
    """Inject a CycloneDX SBOM JSON file into a wheel and update its RECORD."""
    sbom_bytes = json.dumps(sbom, indent=2).encode()
    digest = (
        base64.urlsafe_b64encode(hashlib.sha256(sbom_bytes).digest())
        .rstrip(b"=")
        .decode()
    )

    with zipfile.ZipFile(whl_path, "a") as zf:
        # Find the RECORD file path (also tells us the dist-info dir name)
        record_name = next(
            n for n in zf.namelist() if n.endswith(".dist-info/RECORD")
        )
        dist_info_dir = record_name.rsplit("/", 1)[0]
        sbom_entry = f"{dist_info_dir}/sbom.cdx.json"

        # Add SBOM file
        zf.writestr(sbom_entry, sbom_bytes)

        # Read existing RECORD and append new entry
        record_data = zf.read(record_name).decode()

    record_data = record_data.rstrip("\n")
    record_data += f"\n{sbom_entry},sha256={digest},{len(sbom_bytes)}\n"

    # Rewrite RECORD with updated content (zipfile can't overwrite in-place)
    _rewrite_zip_entry(whl_path, record_name, record_data.encode())
