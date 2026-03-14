"""
client/install.py
Echo-aware pip wrapper. Checks each package against the Echo registry before installing.

Usage:
    python3 client/install.py urllib3==1.26.0 requests==2.28.0
    python3 client/install.py -r requirements.txt
"""

from __future__ import annotations

import sys
import subprocess
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError
import json
import re

REGISTRY_URL = "http://localhost:8000"

import os as _os

# If ECHO_PIP is set (by run.sh), use that pip for actual installs.
# This lets the demo use a separate venv from the tool environment.
_ECHO_PIP = _os.environ.get("ECHO_PIP", "")

# Local artifacts directory for --find-links (avoids pip needing an HTML index URL).
# Try the path relative to this file first, then fall back to the REGISTRY_URL /files/ index.
_ARTIFACTS_DIR = Path(__file__).parent.parent / "factory" / "artifacts"

_G = "\033[0;32m"
_Y = "\033[1;33m"
_R = "\033[0;31m"
_C = "\033[0;36m"
_B = "\033[1m"
_D = "\033[2m"
_X = "\033[0m"


def parse_args(argv: list[str]) -> list[tuple[str, str]]:
    """Parse CLI args and return list of (package, version) pairs."""
    specs: list[str] = []

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-r", "--requirement"):
            i += 1
            req_file = Path(argv[i])
            specs.extend(_read_requirements(req_file))
        elif arg.startswith("-r"):
            req_file = Path(arg[2:])
            specs.extend(_read_requirements(req_file))
        else:
            specs.append(arg)
        i += 1

    result = []
    for spec in specs:
        m = re.match(r"^([A-Za-z0-9_\-\.]+)==(.+)$", spec.strip())
        if m:
            result.append((m.group(1), m.group(2)))
        else:
            spec_stripped = spec.strip()
            if spec_stripped:
                result.append((spec_stripped, None))
    return result


def _read_requirements(path: Path) -> list[str]:
    lines = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def check_package(package: str, version: str) -> dict | None:
    """Call /check/{package}/{version} on registry. Returns parsed JSON or None on failure."""
    url = f"{REGISTRY_URL}/check/{package}/{version}"
    try:
        with urlopen(url, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except URLError as e:
        print(
            f"  {_Y}[ECHO] WARN:{_X} registry unreachable ({e}) — falling back to original spec for {package}",
            file=sys.stderr,
        )
        return None
    except Exception as e:
        print(
            f"  {_Y}[ECHO] WARN:{_X} check failed for {package}=={version}: {e}",
            file=sys.stderr,
        )
        return None


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(f"Usage: python3 client/install.py [-r requirements.txt] [pkg==ver ...]")
        sys.exit(1)

    packages = parse_args(args)
    if not packages:
        print("No packages to install.")
        sys.exit(0)

    install_specs: list[str] = []
    substituted: list[tuple[str, str, str]] = []  # (package, original_ver, patched_ver)
    blocked = False

    for package, version in packages:
        if version is None:
            install_specs.append(package)
            continue

        result = check_package(package, version)

        if result is None:
            # Registry unreachable — fail open
            install_specs.append(f"{package}=={version}")
            continue

        if not result.get("vulnerable"):
            install_specs.append(f"{package}=={version}")
            continue

        cve_id = result["cve_id"]
        severity = result["severity"]
        cvss = result["cvss_score"]
        affected_range = result["version_range"]
        first_patched = result["first_patched_version"]
        artifact = result.get("patched_artifact")

        if severity == "High":
            print(
                f"\n  {_R}[ECHO] ✗ BLOCKED:{_X} {package}=={version} — {_B}{cve_id}{_X} "
                f"({_R}{severity}{_X}, CVSS {cvss})"
            )
            print(f"         Affected range:  {_Y}{affected_range}{_X}")
            print(f"         Quick fix:       pip install '{package}>={first_patched}'")
            if artifact:
                print(
                    f"         Patched build:   {artifact} available but severity requires explicit upgrade"
                )
            blocked = True

        else:
            # Non-high severity — warn and substitute patched artifact
            patched_ver = None
            if artifact:
                # Parse version from filename e.g. requests-2.28.2+echo1-py3-none-any.whl
                m = re.match(r"[^-]+-([^-]+)-", artifact)
                if m:
                    patched_ver = m.group(1).replace("_", "+", 1)

            print(
                f"\n  {_Y}[ECHO] ⚠ WARNING:{_X} {package}=={version} — {_B}{cve_id}{_X} "
                f"({_Y}{severity}{_X}, CVSS {cvss})"
            )
            print(f"         Affected range:  {affected_range}")
            if patched_ver:
                print(f"         Proceeding with patched backport: {_G}{package}-{patched_ver}{_X}")
                print(f"         Recommended fix: pip install '{package}>={first_patched}'")
                install_specs.append(f"{package}=={patched_ver}")
                substituted.append((package, version, patched_ver))
            else:
                # No artifact yet — warn but use original
                print(f"         {_Y}Patched artifact not yet available — using original{_X}")
                print(f"         Recommended fix: pip install '{package}>={first_patched}'")
                install_specs.append(f"{package}=={version}")

    if blocked:
        print(
            f"\n  {_R}[ECHO] BUILD BLOCKED{_X} — one or more High severity CVEs require explicit upgrade."
        )
        print(f"  {_D}Resolve the CVEs above and re-run.{_X}\n")
        sys.exit(1)

    if not install_specs:
        print("Nothing to install.")
        sys.exit(0)

    # Run pip with --find-links pointing to the local artifacts directory.
    # Using a local path ensures pip can find PEP 440 local-version wheels (+echo1)
    # without requiring an HTML index URL.
    find_links = str(_ARTIFACTS_DIR) if _ARTIFACTS_DIR.exists() else f"{REGISTRY_URL}/files/"
    if _ECHO_PIP:
        cmd = [_ECHO_PIP, "install", "--find-links", find_links, *install_specs]
    else:
        cmd = [sys.executable, "-m", "pip", "install", "--find-links", find_links, *install_specs]
    print(f"\n  {_D}Running: {' '.join(cmd)}{_X}\n")
    result_proc = subprocess.run(cmd)

    if result_proc.returncode != 0:
        sys.exit(result_proc.returncode)

    # Post-install injection notices
    for package, original_ver, patched_ver in substituted:
        # Extract dist-info name for SBOM path hint
        dist_tag = patched_ver.replace("+", "").replace(".", "")
        print(
            f"\n  {_C}[ECHO] NOTE:{_X} {package} was forcibly injected with "
            f"{_B}{package}=={patched_ver}{_X}"
        )
        print(f"               instead of requested {package}=={original_ver}")
        print(
            f"               (SBOM embedded — check "
            f"{package}-{patched_ver}.dist-info/sbom.cdx.json)"
        )


if __name__ == "__main__":
    main()
