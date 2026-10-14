from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, List, Optional

from . import paths
from .models import JsonDict, ProjectMetadata


class MetadataError(RuntimeError):
    pass


def load_alert(alert_path: Path) -> JsonDict:
    with alert_path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_project_info(path: Path) -> Dict[str, JsonDict]:
    rows: Dict[str, JsonDict] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            rows[row["cve_id"]] = row
    return rows


def load_build_info(path: Path) -> Dict[str, JsonDict]:
    if not path.exists():
        return {}
    rows: Dict[str, JsonDict] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            rows[row["project_slug"]] = row
    return rows


def normalize_cwe(value: str) -> str:
    return value.strip().upper()


def find_dockerfile(dockerfiles_root: Path, project_slug: str) -> Path:
    project_dir = dockerfiles_root / project_slug
    matches = sorted(project_dir.glob("*/Dockerfile"))
    if not matches:
        raise MetadataError(f"No Dockerfile found for {project_slug} under {project_dir}")
    if len(matches) > 1:
        joined = ", ".join(str(match) for match in matches)
        raise MetadataError(f"Multiple Dockerfiles found for {project_slug}: {joined}")
    return matches[0]


def detect_build_defaults(source_path: Path, build_row: JsonDict) -> JsonDict:
    if (source_path / "gradlew").exists():
        return {
            "build_system": "gradle-wrapper",
            "build_command": "./gradlew --no-daemon clean build -x test",
            "test_command": "./gradlew --no-daemon test",
        }
    if (source_path / "pom.xml").exists():
        return {
            "build_system": "maven",
            "build_command": "mvn -B -DskipTests package",
            "test_command": "mvn -B test",
        }
    if (source_path / "build.gradle").exists() or (source_path / "build.gradle.kts").exists():
        return {
            "build_system": "gradle",
            "build_command": "gradle --no-daemon clean build -x test",
            "test_command": "gradle --no-daemon test",
        }
    return {
        "build_system": "unknown",
        "build_command": build_row.get("build_command", ""),
        "test_command": build_row.get("test_command", ""),
    }


def resolve_project_metadata(alert_path: Path, workspace_root: Path) -> ProjectMetadata:
    alert = load_alert(alert_path)
    cve_id = alert.get("cve_id")
    if not cve_id:
        raise MetadataError(f"Alert {alert_path} does not include cve_id")

    project_rows = load_project_info(paths.project_info_csv(workspace_root))
    row = project_rows.get(cve_id)
    if row is None:
        raise MetadataError(f"No project_info.csv row found for {cve_id}")

    project_slug = row["project_slug"]
    source_path = paths.project_source(workspace_root, project_slug)
    if not source_path.exists():
        raise MetadataError(f"Project source tree is missing: {source_path}")

    dockerfile_path = find_dockerfile(paths.dockerfiles_dir(workspace_root), project_slug)
    build_rows = load_build_info(paths.build_info_csv(workspace_root))
    build_row = build_rows.get(project_slug, {})
    defaults = detect_build_defaults(source_path, build_row)

    return ProjectMetadata(
        project_slug=project_slug,
        cve_id=row.get("cve_id", cve_id),
        cwe_id=normalize_cwe(row.get("cwe_id") or alert.get("cwe_id", "")),
        cwe_name=row.get("cwe_name", ""),
        github_url=row.get("github_url", ""),
        github_tag=row.get("github_tag", ""),
        buggy_commit_id=row.get("buggy_commit_id", ""),
        fix_commit_ids=row.get("fix_commit_ids", ""),
        source_path=source_path,
        dockerfile_path=dockerfile_path,
        build_system=defaults["build_system"],
        build_command=defaults["build_command"],
        test_command=defaults["test_command"],
        jdk_version=build_row.get("jdk_version", ""),
        mvn_version=build_row.get("mvn_version", ""),
        gradle_version=build_row.get("gradle_version", ""),
        use_gradlew=build_row.get("use_gradlew", ""),
        docker_platform=build_row.get("docker_platform", ""),
    )


def load_project_info_by_slug(path: Path) -> Dict[str, JsonDict]:
    rows: Dict[str, JsonDict] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            rows[row["project_slug"]] = row
    return rows


def resolve_project_metadata_by_slug(project_slug: str, workspace_root: Path) -> ProjectMetadata:
    """Build ProjectMetadata directly from a project slug (no alert needed).

    Mirrors ``resolve_project_metadata`` but keyed by ``project_slug`` instead of
    an alert's CVE. Used by the ``fixpov`` command group, which certifies a
    project's fixPOVs without going through an alert.
    """
    project_rows = load_project_info_by_slug(paths.project_info_csv(workspace_root))
    row = project_rows.get(project_slug)
    if row is None:
        raise MetadataError(f"No project_info.csv row found for project slug {project_slug}")

    source_path = paths.project_source(workspace_root, project_slug)
    if not source_path.exists():
        raise MetadataError(f"Project source tree is missing: {source_path}")

    dockerfile_path = find_dockerfile(paths.dockerfiles_dir(workspace_root), project_slug)
    build_rows = load_build_info(paths.build_info_csv(workspace_root))
    build_row = build_rows.get(project_slug, {})
    defaults = detect_build_defaults(source_path, build_row)

    return ProjectMetadata(
        project_slug=project_slug,
        cve_id=row.get("cve_id", ""),
        cwe_id=normalize_cwe(row.get("cwe_id", "")),
        cwe_name=row.get("cwe_name", ""),
        github_url=row.get("github_url", ""),
        github_tag=row.get("github_tag", ""),
        buggy_commit_id=row.get("buggy_commit_id", ""),
        fix_commit_ids=row.get("fix_commit_ids", ""),
        source_path=source_path,
        dockerfile_path=dockerfile_path,
        build_system=defaults["build_system"],
        build_command=defaults["build_command"],
        test_command=defaults["test_command"],
        jdk_version=build_row.get("jdk_version", ""),
        mvn_version=build_row.get("mvn_version", ""),
        gradle_version=build_row.get("gradle_version", ""),
        use_gradlew=build_row.get("use_gradlew", ""),
        docker_platform=build_row.get("docker_platform", ""),
    )


def alert_paths_for_cve(alerts_dir: Path, cve_id: str) -> List[Path]:
    matches: List[Path] = []
    for path in sorted(alerts_dir.glob("*.json")):
        try:
            alert = load_alert(path)
        except json.JSONDecodeError:
            continue
        if alert.get("cve_id") == cve_id:
            matches.append(path)
    return matches


def all_alert_paths(alerts_dir: Path) -> List[Path]:
    return sorted(alerts_dir.glob("*.json"))


def choose_alerts(alerts_dir: Path, alert: Optional[Path], cve: Optional[str], run_all: bool) -> List[Path]:
    selected = sum([alert is not None, cve is not None, run_all])
    if selected != 1:
        raise MetadataError("Choose exactly one of --alert, --cve, or --all")
    if alert is not None:
        path = alert if alert.is_absolute() else Path.cwd() / alert
        if not path.exists():
            raise MetadataError(f"Alert file does not exist: {path}")
        return [path]
    if cve is not None:
        matches = alert_paths_for_cve(alerts_dir, cve)
        if not matches:
            raise MetadataError(f"No alert found for {cve} under {alerts_dir}")
        return matches
    return all_alert_paths(alerts_dir)
