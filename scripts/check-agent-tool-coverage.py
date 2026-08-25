#!/usr/bin/env python3
"""Compare enabled tools/*.yaml definitions to the locked image mapping."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None


ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "tools"
MAPPING = ROOT / "container" / "agent" / "tool-mapping.json"
LOCK = ROOT / "container" / "agent" / "toolchain.lock"
REQUIREMENTS = ROOT / "container" / "agent" / "requirements-tools.txt"
CHECKOV_REQUIREMENTS = ROOT / "container" / "agent" / "requirements-checkov.txt"
PLATFORMS = ("linux/amd64", "linux/arm64")


def parse_enabled_yaml_names(tools_dir: Path) -> set[str]:
    enabled: set[str] = set()
    for path in sorted(tools_dir.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        name = None
        is_enabled = True
        if yaml is not None:
            try:
                data = yaml.safe_load(text) or {}
                name = data.get("name") or path.stem
                is_enabled = bool(data.get("enabled", True))
            except Exception:
                name = None
        if name is None:
            for line in text.splitlines():
                if line.startswith("name:"):
                    name = line.split(":", 1)[1].strip().strip("\"'")
                elif line.startswith("enabled:"):
                    is_enabled = line.split(":", 1)[1].strip().lower() in ("true", "yes", "1")
            name = name or path.stem
        if is_enabled:
            enabled.add(name)
    return enabled


def load_mapping_names(mapping_path: Path) -> set[str]:
    data = json.loads(mapping_path.read_text(encoding="utf-8"))
    tools = data.get("tools") or data.get("tool_map") or []
    return {t["yaml_name"] for t in tools}


def load_lock_tool_map_names(lock_path: Path) -> set[str]:
    if not lock_path.is_file():
        return set()
    data = json.loads(lock_path.read_text(encoding="utf-8"))
    return {t["yaml_name"] for t in data.get("tool_map", [])}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def platform_map(rows: list[dict]) -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}
    for row in rows:
        platforms = row.get("supported_platforms", list(PLATFORMS))
        result[row["yaml_name"]] = tuple(sorted(platforms))
    return result


def normalized_package(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def missing_locked_packages(mapping_rows: list[dict], lock_data: dict) -> dict[str, list[str]]:
    """Ensure every package-backed tool is present in its installer lock."""
    locked = {
        "apt": set(lock_data.get("apt_packages", [])),
        "pip": {
            normalized_package(row["name"])
            for row in lock_data.get("pip_packages", [])
        },
        "gem": {row["name"] for row in lock_data.get("gem_packages", [])},
        "npm": {row["name"] for row in lock_data.get("npm_packages", [])},
        "go": {row["path"] for row in lock_data.get("go_modules", [])},
        "github": (
            {row["id"] for row in lock_data.get("github_releases", [])}
            | {
                f'{row["repo"]}@{row["tag"]}'
                for row in lock_data.get("github_releases", [])
            }
        ),
        "bash_script": {row["name"] for row in lock_data.get("git_sources", [])},
    }
    missing: dict[str, list[str]] = {}
    for method, packages in locked.items():
        expected = {
            normalized_package(row["package"]) if method == "pip" else row["package"]
            for row in mapping_rows
            if row.get("install_method") == method
        }
        absent = sorted(expected - packages)
        if absent:
            missing[method] = absent
    return missing


def parse_requirements(path: Path) -> dict[str, str]:
    packages: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            raise ValueError(f"unpinned requirement: {line}")
        name, version = line.split("==", 1)
        packages[normalized_package(name)] = version
    return packages


def find_placeholders(value: object, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            found.extend(find_placeholders(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(find_placeholders(child, f"{path}[{index}]"))
    elif isinstance(value, str) and "PLACEHOLDER" in value.upper():
        found.append(path)
    return found


def validate_release_locks(lock_data: dict) -> list[str]:
    errors: list[str] = []
    for row in lock_data.get("github_releases", []):
        release_id = row.get("id", "<missing-id>")
        architectures = row.get("supported_architectures", ["amd64", "arm64"])
        invalid = sorted(set(architectures) - {"amd64", "arm64"})
        if invalid:
            errors.append(f"{release_id}: invalid architectures {invalid}")
        for arch in architectures:
            digest = row.get(f"sha256_{arch}", "")
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                errors.append(f"{release_id}: invalid sha256_{arch}")
            has_asset = bool(
                row.get(f"asset_{arch}")
                or row.get("asset_name")
                or row.get(f"download_url_{arch}")
                or row.get("download_url_template")
            )
            if not has_asset:
                errors.append(f"{release_id}: no explicit asset/url for {arch}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools-dir", type=Path, default=TOOLS_DIR)
    parser.add_argument("--mapping", type=Path, default=MAPPING)
    parser.add_argument("--lock", type=Path, default=LOCK)
    parser.add_argument("--requirements", type=Path, default=REQUIREMENTS)
    parser.add_argument("--checkov-requirements", type=Path, default=CHECKOV_REQUIREMENTS)
    parser.add_argument("--json", action="store_true", help="machine-readable summary")
    args = parser.parse_args()

    enabled = parse_enabled_yaml_names(args.tools_dir)
    mapping_data = load_json(args.mapping)
    lock_data = load_json(args.lock)
    mapping_rows = mapping_data.get("tools", [])
    lock_rows = lock_data.get("tool_map", [])
    mapped = {t["yaml_name"] for t in mapping_rows}
    locked = {t["yaml_name"] for t in lock_rows}

    missing = sorted(enabled - mapped)
    extra = sorted(mapped - enabled)
    lock_missing = sorted(enabled - locked) if locked else []
    lock_extra = sorted(locked - enabled) if locked else []

    mapping_platforms = platform_map(mapping_rows)
    lock_platforms = platform_map(lock_rows)
    platform_mismatches = sorted(
        name for name in mapped & locked if mapping_platforms[name] != lock_platforms[name]
    )
    invalid_platform_rows = sorted(
        name
        for name, platforms in mapping_platforms.items()
        if not platforms or set(platforms) - set(PLATFORMS)
    )
    placeholders = find_placeholders(lock_data)
    release_lock_errors = validate_release_locks(lock_data)
    missing_installer_locks = missing_locked_packages(mapping_rows, lock_data)

    requirements = parse_requirements(args.requirements)
    checkov_requirements = parse_requirements(args.checkov_requirements)
    overlap = set(requirements) & set(checkov_requirements)
    if overlap:
        raise ValueError(f"requirements duplicated across Python environments: {sorted(overlap)}")
    requirements.update(checkov_requirements)
    locked_pip = {
        normalized_package(row["name"]): row["version"]
        for row in lock_data.get("pip_packages", [])
    }
    pip_lock_mismatches = sorted(
        name
        for name in set(requirements) | set(locked_pip)
        if requirements.get(name) != locked_pip.get(name)
    )

    platform_available = {
        platform: sum(platform in mapping_platforms[name] for name in enabled & mapped)
        for platform in PLATFORMS
    }

    ok = not missing and not extra and len(enabled) == len(mapped)
    if locked:
        ok = ok and not lock_missing and not lock_extra
    ok = ok and not platform_mismatches and not invalid_platform_rows
    ok = ok and not placeholders and not release_lock_errors and not pip_lock_mismatches
    ok = ok and not missing_installer_locks

    summary = {
        "enabled_count": len(enabled),
        "mapping_count": len(mapped),
        "lock_tool_map_count": len(locked),
        "missing_in_mapping": missing,
        "extra_in_mapping": extra,
        "missing_in_lock": lock_missing,
        "extra_in_lock": lock_extra,
        "platform_mismatches": platform_mismatches,
        "invalid_platform_rows": invalid_platform_rows,
        "placeholder_paths": placeholders,
        "release_lock_errors": release_lock_errors,
        "pip_lock_mismatches": pip_lock_mismatches,
        "missing_installer_locks": missing_installer_locks,
        "platform_available": platform_available,
        "ok": ok,
        "ratio": f"{len(mapped & enabled)}/{len(enabled)}",
    }

    if args.json:
        json.dump(summary, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        print(f"enabled YAML tools: {summary['enabled_count']}")
        print(f"tool-mapping.json:  {summary['mapping_count']}")
        if locked:
            print(f"toolchain.lock map: {summary['lock_tool_map_count']}")
        print(f"coverage: {summary['ratio']}")
        if missing:
            print("missing in mapping:")
            for n in missing:
                print(f"  - {n}")
        if extra:
            print("extra in mapping:")
            for n in extra:
                print(f"  - {n}")
        if lock_missing:
            print("missing in toolchain.lock tool_map:")
            for n in lock_missing:
                print(f"  - {n}")
        if lock_extra:
            print("extra in toolchain.lock tool_map:")
            for n in lock_extra:
                print(f"  - {n}")
        if platform_mismatches:
            print("platform support differs between mapping and lock:")
            for n in platform_mismatches:
                print(f"  - {n}")
        if invalid_platform_rows:
            print("invalid supported_platforms:")
            for n in invalid_platform_rows:
                print(f"  - {n}")
        if placeholders:
            print("placeholder values in toolchain.lock:")
            for n in placeholders:
                print(f"  - {n}")
        if release_lock_errors:
            print("invalid release locks:")
            for error in release_lock_errors:
                print(f"  - {error}")
        if pip_lock_mismatches:
            print("requirements/toolchain pip mismatches:")
            for n in pip_lock_mismatches:
                print(f"  - {n}")
        if missing_installer_locks:
            print("mapping packages absent from installer locks:")
            for method, packages in missing_installer_locks.items():
                for package in packages:
                    print(f"  - {method}: {package}")
        for platform, available in platform_available.items():
            print(f"{platform} declared availability: {available}/{len(enabled)}")
        print("PASS" if ok else "FAIL")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
