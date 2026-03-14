"""
factory/builder.py
Demand-driven backport wheel builder for Echo demo.

Run from the project root:
    python3 factory/builder.py
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests as _requests
from packaging.specifiers import SpecifierSet
from packaging.version import Version

sys.path.insert(0, str(Path(__file__).parent.parent))
from db.schema import get_connection, init_db
from factory.sbom import generate_sbom, inject_sbom_into_wheel

ARTIFACTS_DIR = Path(__file__).parent / "artifacts"
PYPI_JSON_URL = "https://pypi.org/pypi/{package}/{version}/json"

_G = "\033[0;32m"
_Y = "\033[1;33m"
_R = "\033[0;31m"
_C = "\033[0;36m"
_B = "\033[1m"
_X = "\033[0m"


# ── PyPI helpers ───────────────────────────────────────────────────────────────

def get_sdist_url(package: str, version: str) -> str:
    resp = _requests.get(PYPI_JSON_URL.format(package=package, version=version), timeout=30)
    resp.raise_for_status()
    sdist_entries = [u for u in resp.json()["urls"] if u["packagetype"] == "sdist"]
    if not sdist_entries:
        raise RuntimeError(f"No sdist found for {package}=={version} on PyPI")
    return sdist_entries[0]["url"]


def download_tarball(url: str, dest: Path) -> None:
    resp = _requests.get(url, stream=True, timeout=60)
    resp.raise_for_status()
    with open(dest, "wb") as fh:
        for chunk in resp.iter_content(chunk_size=65536):
            fh.write(chunk)


# ── tarball helpers ────────────────────────────────────────────────────────────

def get_top_level_dir(tarball: Path) -> str:
    with tarfile.open(tarball, "r:gz") as tf:
        first = tf.getnames()[0]
    return first.rstrip("/").split("/")[0]


def extract_and_rename(tarball: Path, workdir: Path, target_name: str) -> Path:
    top = get_top_level_dir(tarball)
    with tarfile.open(tarball, "r:gz") as tf:
        tf.extractall(workdir, filter="data")
    renamed = workdir / target_name
    if renamed.exists():
        shutil.rmtree(renamed)
    (workdir / top).rename(renamed)
    return renamed


# ── version-string helpers ─────────────────────────────────────────────────────

def _find_version_file(source_dir: Path, version: str) -> Path | None:
    candidates: list[Path] = []

    for pattern in ("**/_version.py", "**/__version__.py", "**/__init__.py"):
        candidates.extend(sorted(source_dir.glob(pattern)))

    for name in ("setup.cfg", "pyproject.toml", "setup.py"):
        p = source_dir / name
        if p.exists():
            candidates.append(p)

    pyproject = source_dir / "pyproject.toml"
    if pyproject.exists():
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                tomllib = None
        if tomllib is not None:
            try:
                data = tomllib.loads(pyproject.read_text())
                hatch_path = data.get("tool", {}).get("hatch", {}).get("version", {}).get("path")
                if hatch_path:
                    candidates.insert(0, source_dir / hatch_path)
            except Exception:
                pass

    for path in candidates:
        try:
            if version in path.read_text(errors="replace"):
                return path
        except OSError:
            continue
    return None


def bump_version(source_dir: Path, old_version: str, new_version: str) -> bool:
    found = False

    version_file = _find_version_file(source_dir, old_version)
    if version_file is None:
        print(f"  [WARN] Could not locate version string '{old_version}' in {source_dir}")
    else:
        text = version_file.read_text(errors="replace")
        new_text = text.replace(f'"{old_version}"', f'"{new_version}"')
        new_text = new_text.replace(f"'{old_version}'", f"'{new_version}'")
        if new_text == text:
            print(f"  [WARN] Version string '{old_version}' unchanged in {version_file}")
        else:
            version_file.write_text(new_text)
            print(f"  Bumped {version_file.relative_to(source_dir)}: {old_version!r} → {new_version!r}")
            found = True

    pkg_info = source_dir / "PKG-INFO"
    if pkg_info.exists():
        text = pkg_info.read_text(errors="replace")
        new_text = re.sub(
            rf"^(Version:\s*){re.escape(old_version)}\s*$",
            f"\\g<1>{new_version}",
            text,
            flags=re.MULTILINE,
        )
        if new_text != text:
            pkg_info.write_text(new_text)
            print(f"  Bumped PKG-INFO Version: {old_version!r} → {new_version!r}")
            found = True

    pyproject = source_dir / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text(errors="replace")
        vf_match = re.search(r'version-file\s*=\s*["\']([^"\']+)["\']', text)
        version_file_path = vf_match.group(1) if vf_match else f"src/{source_dir.name}/_version.py"

        patched = text
        patched = re.sub(r'source\s*=\s*["\']vcs["\']', f'path = "{version_file_path}"', patched)
        patched = re.sub(r'\[tool\.hatch\.version\.raw-options\][^\[]*', '', patched, flags=re.DOTALL)
        patched = re.sub(r'\[tool\.hatch\.build\.hooks\.vcs\][^\[]*', '', patched, flags=re.DOTALL)
        if patched != text:
            pyproject.write_text(patched)
            print("  Patched pyproject.toml: disabled hatch-vcs source + local-version strip")

    return found


# ── patch helpers ──────────────────────────────────────────────────────────────

_NOISE_PATTERNS = re.compile(
    r'^(test[s]?/|docs?/|dummyserver/|\.github/|'
    r'.*\.(rst|md|lock)|PKG-INFO|CHANGES|README|LICENSE|'
    r'.*_version\.py|.*__version__\.py)',
    re.IGNORECASE,
)


def _filter_source_patch(patch_text: str, package_name: str) -> str:
    if not patch_text.strip():
        return patch_text

    kept_blocks = []
    raw_blocks = re.split(r'(?=^diff -ru )', patch_text, flags=re.MULTILINE)

    for block in raw_blocks:
        if not block.strip():
            continue
        m = re.match(r'diff -ru \S+/(\S+) ', block)
        if not m:
            kept_blocks.append(block)
            continue
        filepath = m.group(1)
        if _NOISE_PATTERNS.match(filepath):
            continue
        kept_blocks.append(block)

    return "".join(kept_blocks)


def make_patch(workdir: Path, patch_dest: Path) -> None:
    result = subprocess.run(
        ["diff", "-ru", "old", "new"],
        cwd=workdir,
        capture_output=True,
        text=True,
    )
    if result.returncode == 2:
        raise RuntimeError(f"diff failed (exit 2):\n{result.stderr}")
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    patch_dest.write_text(result.stdout)
    print(f"  Patch written ({len(result.stdout)} bytes): {patch_dest.name}")


def apply_patch(workdir: Path, patch_file: Path) -> bool:
    patch_text = patch_file.read_text()
    if not patch_text.strip():
        print("  Patch is empty (versions are identical) — skipping apply.")
        return True
    result = subprocess.run(
        ["patch", "-p1", "-d", "old/"],
        input=patch_text,
        cwd=workdir,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        print("  Patch applied cleanly.")
        return True
    elif result.returncode == 1:
        print(f"  [WARN] Patch applied with hunk failures:\n{result.stdout}\n{result.stderr}")
        return False
    else:
        raise RuntimeError(f"patch error (exit {result.returncode}):\n{result.stderr}")


# ── wheel build helpers ────────────────────────────────────────────────────────

def build_wheel(source_dir: Path, dist_dir: Path) -> Path:
    dist_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(dist_dir), str(source_dir)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"wheel build failed:\n{result.stdout}\n{result.stderr}")
    wheels = list(dist_dir.glob("*.whl"))
    if not wheels:
        raise RuntimeError("build succeeded but no .whl file found")
    return wheels[0]


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ── SQLite-backed demand filter ────────────────────────────────────────────────

def get_eligible_groups() -> list[dict]:
    """
    Returns unbuilt version_groups where at least one request_log entry for the
    same package has a version falling inside the group's version_range AND
    last_requested within the last 30 days.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")

    with get_connection() as conn:
        groups = conn.execute(
            """
            SELECT vg.id, vg.cve_id, vg.version_range, vg.pivot_version,
                   c.package, c.severity, c.cvss_score, c.first_patched_version, c.description
            FROM version_groups vg
            JOIN cves c ON c.cve_id = vg.cve_id
            WHERE vg.artifact_filename IS NULL
            ORDER BY vg.id
            """
        ).fetchall()

        recent_requests = conn.execute(
            """
            SELECT package, version FROM request_log
            WHERE last_requested > ?
            """,
            (cutoff,),
        ).fetchall()

    eligible = []
    for g in groups:
        try:
            spec = SpecifierSet(g["version_range"])
        except Exception:
            continue
        for req in recent_requests:
            if req["package"] != g["package"]:
                continue
            try:
                if Version(req["version"]) in spec:
                    eligible.append(dict(g))
                    break
            except Exception:
                continue

    return eligible


def update_group_artifact(group_id: int, filename: str, sha256: str) -> None:
    built_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE version_groups
            SET artifact_filename = ?, artifact_sha256 = ?, built_at = ?
            WHERE id = ?
            """,
            (filename, sha256, built_at, group_id),
        )


# ── Main build logic ───────────────────────────────────────────────────────────

def build_group(group: dict) -> None:
    cve_id: str = group["cve_id"]
    package: str = group["package"]
    pivot: str = group["pivot_version"]
    first_patched: str = group["first_patched_version"]
    bumped_version = f"{pivot}+echo1"

    patch_path = ARTIFACTS_DIR / f"{cve_id}.patch"

    print(f"\n{_C}[{cve_id}]{_X} {_B}{package}{_X} pivot={pivot} range={group['version_range']}")

    with tempfile.TemporaryDirectory(prefix="echo_build_") as _tmpdir:
        workdir = Path(_tmpdir)

        print("  Fetching sdist URLs ...")
        try:
            old_url = get_sdist_url(package, pivot)
            new_url = get_sdist_url(package, first_patched)
        except Exception as exc:
            print(f"  {_R}[ERROR]{_X} PyPI fetch failed: {exc} — skipping.")
            return

        print(f"  Downloading old ({pivot}) ...")
        old_tarball = workdir / f"{package}-{pivot}.tar.gz"
        try:
            download_tarball(old_url, old_tarball)
        except Exception as exc:
            print(f"  {_R}[ERROR]{_X} Download failed: {exc} — skipping.")
            return

        print(f"  Downloading new ({first_patched}) ...")
        new_tarball = workdir / f"{package}-{first_patched}.tar.gz"
        try:
            download_tarball(new_url, new_tarball)
        except Exception as exc:
            print(f"  {_R}[ERROR]{_X} Download failed: {exc} — skipping.")
            return

        print("  Extracting ...")
        try:
            old_dir = extract_and_rename(old_tarball, workdir, "old")
            extract_and_rename(new_tarball, workdir, "new")
        except Exception as exc:
            print(f"  {_R}[ERROR]{_X} Extraction failed: {exc} — skipping.")
            return

        print("  Running diff ...")
        try:
            make_patch(workdir, patch_path)
        except Exception as exc:
            print(f"  {_R}[ERROR]{_X} diff failed: {exc} — skipping.")
            return

        raw_patch = patch_path.read_text()
        filtered = _filter_source_patch(raw_patch, package)
        if filtered != raw_patch:
            dropped = raw_patch.count("\ndiff -ru ") - filtered.count("\ndiff -ru ")
            kept = filtered.count("\ndiff -ru ") + (1 if filtered.startswith("diff") else 0)
            print(f"  Filtered patch: kept {kept} source file(s), dropped {dropped} noise file(s)")
            patch_path.write_text(filtered)

        print("  Applying patch ...")
        try:
            apply_patch(workdir, patch_path)
        except Exception as exc:
            print(f"  [WARN] {exc} — continuing.")

        print(f"  Bumping version to {bumped_version!r} ...")
        bump_version(old_dir, first_patched, bumped_version)
        bump_version(old_dir, pivot, bumped_version)

        print("  Building wheel ...")
        dist_dir = workdir / "dist"
        try:
            wheel_path = build_wheel(old_dir, dist_dir)
            print(f"  Built: {wheel_path.name}")
        except RuntimeError as exc:
            print(f"  {_R}[WARN]{_X} Wheel build failed: {exc}")
            return

        dest_wheel = ARTIFACTS_DIR / wheel_path.name
        shutil.copy2(wheel_path, dest_wheel)

        # Inject SBOM
        print("  Injecting SBOM ...")
        sbom_data = generate_sbom(
            package=package,
            pivot_version=pivot,
            first_patched=first_patched,
            cve_id=cve_id,
            severity=group["severity"],
            cvss=group["cvss_score"],
            description=group["description"],
        )
        inject_sbom_into_wheel(dest_wheel, sbom_data)
        print(f"  {_G}SBOM injected:{_X} {dest_wheel.name}")

        whl_sha256 = sha256_of(dest_wheel)
        print(f"  sha256={whl_sha256[:16]}...  size={dest_wheel.stat().st_size}")

        update_group_artifact(group["id"], dest_wheel.name, whl_sha256)
        print(f"  {_G}✓{_X} Saved: {dest_wheel.name}")


def main() -> None:
    init_db()
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    # Show skipped (pre-built) groups
    with get_connection() as conn:
        prebuilt = conn.execute(
            """
            SELECT vg.id, c.package, vg.pivot_version, vg.artifact_filename
            FROM version_groups vg JOIN cves c ON c.cve_id = vg.cve_id
            WHERE vg.artifact_filename IS NOT NULL
            ORDER BY vg.id
            """
        ).fetchall()

    if prebuilt:
        print(f"\n{_B}Pre-built artifacts (skipped):{_X}")
        for r in prebuilt:
            print(f"  {_G}[skip]{_X} {r['package']} pivot={r['pivot_version']} → {r['artifact_filename']}")

    eligible = get_eligible_groups()

    if not eligible:
        print(f"\n{_Y}No eligible groups to build (demand filter: 30-day window).{_X}")
        return

    print(f"\n{_B}Building {len(eligible)} eligible group(s):{_X}")
    for group in eligible:
        build_group(group)

    print(f"\n{_G}Builder done.{_X}")


if __name__ == "__main__":
    main()
