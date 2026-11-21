"""Offline customer artifact scanner entrypoint for an isolated ECS Fargate task."""

from __future__ import annotations

import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any

WORK = pathlib.Path("/tmp/cloudsentinel-scan")
MAX_UPLOAD = 250 * 1024 * 1024
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_FILES = 20_000
MAX_FINDINGS = 2_000
MAX_RESULT_BYTES = 2 * 1024 * 1024
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}


def _safe_name(raw: str) -> str:
    name = pathlib.PurePath(raw.replace("\\", "/")).name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:180]
    if name in {"", ".", ".."}:
        return "artifact"
    return name


def _download(url: str, destination: pathlib.Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "CloudSentinel-Isolated-Scanner"})
    total = 0
    with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_UPLOAD:
                raise ValueError("artifact_too_large")
            output.write(chunk)


def _safe_extract_zip(source: pathlib.Path, destination: pathlib.Path) -> int:
    written = 0
    with zipfile.ZipFile(source) as archive:
        members = archive.infolist()
        if len(members) > MAX_FILES:
            raise ValueError("archive_file_limit")
        for member in members:
            path = pathlib.PurePosixPath(member.filename)
            mode = member.external_attr >> 16
            if path.is_absolute() or ".." in path.parts or (mode & 0o170000) == 0o120000:
                raise ValueError("unsafe_archive_path")
            written += member.file_size
            if written > MAX_EXPANDED:
                raise ValueError("archive_expansion_limit")
            target = destination.joinpath(*path.parts)
            if not target.resolve().is_relative_to(destination.resolve()):
                raise ValueError("unsafe_archive_path")
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source_file, target.open("wb") as target_file:
                shutil.copyfileobj(source_file, target_file, length=1024 * 1024)
    return written


def _safe_extract_tar(source: pathlib.Path, destination: pathlib.Path) -> int:
    written = 0
    with tarfile.open(source, mode="r:*") as archive:
        members = archive.getmembers()
        if len(members) > MAX_FILES:
            raise ValueError("archive_file_limit")
        for member in members:
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError("unsafe_archive_path")
            written += member.size
            if written > MAX_EXPANDED:
                raise ValueError("archive_expansion_limit")
            target = destination.joinpath(*path.parts)
            if not target.resolve().is_relative_to(destination.resolve()):
                raise ValueError("unsafe_archive_path")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            source_file = archive.extractfile(member)
            if source_file is None:
                raise ValueError("invalid_archive")
            target.parent.mkdir(parents=True, exist_ok=True)
            with source_file, target.open("wb") as target_file:
                shutil.copyfileobj(source_file, target_file, length=1024 * 1024)
    return written


def _extract_iac(source: pathlib.Path, source_name: str) -> pathlib.Path:
    destination = WORK / "source"
    destination.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(source):
        _safe_extract_zip(source, destination)
    elif tarfile.is_tarfile(source):
        _safe_extract_tar(source, destination)
    else:
        shutil.copyfile(source, destination / _safe_name(source_name))
    if not any(path.is_file() for path in destination.rglob("*")):
        raise ValueError("empty_archive")
    return destination


def _bounded(value: object, limit: int) -> str:
    text = str(value or "").replace("\x00", " ").strip()
    return text[:limit]


def _severity(value: object) -> str:
    normalized = _bounded(value, 20).upper()
    return normalized if normalized in SEVERITIES else "UNKNOWN"


def _normalize_trivy(payload: dict[str, Any], scan_type: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in payload.get("Results", []) if isinstance(payload.get("Results"), list) else []:
        if not isinstance(result, dict):
            continue
        resource = _bounded(result.get("Target"), 700)
        misconfigs = result.get("Misconfigurations", [])
        for finding in misconfigs if isinstance(misconfigs, list) else []:
            if not isinstance(finding, dict):
                continue
            findings.append({
                "rule_id": _bounded(finding.get("ID"), 160) or "TRIVY-MISCONFIG",
                "title": _bounded(finding.get("Title"), 500) or "Configuration risk",
                "severity": _severity(finding.get("Severity")),
                "category": "misconfiguration",
                "resource": _bounded(finding.get("Resource") or resource, 700) or None,
                "details": {"message": _bounded(finding.get("Message"), 4000), "primary_url": _bounded(finding.get("PrimaryURL"), 500)},
            })
        vulnerabilities = result.get("Vulnerabilities", [])
        for finding in vulnerabilities if isinstance(vulnerabilities, list) else []:
            if not isinstance(finding, dict):
                continue
            findings.append({
                "rule_id": _bounded(finding.get("VulnerabilityID"), 160) or "TRIVY-VULNERABILITY",
                "title": _bounded(finding.get("Title") or finding.get("PkgName"), 500) or "Vulnerable package",
                "severity": _severity(finding.get("Severity")),
                "category": "vulnerability",
                "resource": _bounded(finding.get("PkgName") or resource, 700) or None,
                "details": {"installed_version": _bounded(finding.get("InstalledVersion"), 200), "fixed_version": _bounded(finding.get("FixedVersion"), 200), "primary_url": _bounded(finding.get("PrimaryURL"), 500)},
            })
        secrets = result.get("Secrets", [])
        for finding in secrets if isinstance(secrets, list) else []:
            if not isinstance(finding, dict):
                continue
            findings.append({
                "rule_id": _bounded(finding.get("RuleID"), 160) or "TRIVY-SECRET",
                "title": _bounded(finding.get("Title"), 500) or "Potential secret",
                "severity": _severity(finding.get("Severity")),
                "category": "secret",
                "resource": _bounded(finding.get("Target") or resource, 700) or None,
                "details": {"match": "[REDACTED]"},
            })
    return findings[:MAX_FINDINGS]


def _normalize_checkov(payload: object) -> list[dict[str, Any]]:
    reports = payload if isinstance(payload, list) else [payload]
    findings: list[dict[str, Any]] = []
    for report in reports:
        if not isinstance(report, dict):
            continue
        failed = report.get("results", {}).get("failed_checks", []) if isinstance(report.get("results"), dict) else []
        for finding in failed if isinstance(failed, list) else []:
            if not isinstance(finding, dict):
                continue
            check_id = _bounded(finding.get("check_id"), 160)
            findings.append({
                "rule_id": check_id or "CHECKOV-MISCONFIG",
                "title": _bounded(finding.get("check_name"), 500) or check_id or "Infrastructure misconfiguration",
                "severity": _severity(finding.get("severity") or "MEDIUM"),
                "category": "misconfiguration",
                "resource": _bounded(finding.get("resource"), 700) or None,
                "details": {"file_path": _bounded(finding.get("file_path"), 700), "file_line_range": finding.get("file_line_range", []), "guideline": _bounded(finding.get("guideline"), 1000)},
            })
    return findings[:MAX_FINDINGS]


def _scan(scan_type: str, source: pathlib.Path, source_name: str) -> tuple[list[dict[str, Any]], str]:
    if scan_type == "iac":
        root = _extract_iac(source, source_name)
        command = ["checkov", "-d", str(root), "--quiet", "--output", "json", "--compact"]
        process = subprocess.run(command, capture_output=True, text=True, timeout=600, check=False)
        if process.returncode not in {0, 1}:
            raise RuntimeError("iac_scanner_failed")
        return _normalize_checkov(json.loads(process.stdout or "[]")), f"checkov-{_bounded(_version('checkov'), 40)}"
    if scan_type == "container":
        command = [
            "trivy", "image", "--input", str(source), "--format", "json",
            "--scanners", "vuln,misconfig,secret", "--skip-db-update",
            "--skip-java-db-update", "--skip-check-update", "--offline-scan",
            "--timeout", "10m", "--cache-dir", "/opt/trivy-cache",
        ]
        process = subprocess.run(command, capture_output=True, text=True, timeout=660, check=False)
        if process.returncode != 0:
            raise RuntimeError("container_scanner_failed")
        return _normalize_trivy(json.loads(process.stdout or "{}"), scan_type), f"trivy-{_bounded(_version('trivy'), 40)}"
    raise ValueError("unsupported_scan_type")


def _version(binary: str) -> str:
    process = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=15, check=False)
    return (process.stdout or process.stderr).splitlines()[0] if process.returncode == 0 else "unknown"


def _publish(payload: dict[str, Any], url: str) -> None:
    encoded = json.dumps(payload, separators=(",", ":")).encode()
    if len(encoded) > MAX_RESULT_BYTES:
        raise ValueError("result_too_large")
    request = urllib.request.Request(
        url,
        data=encoded,
        method="PUT",
        headers={"Content-Type": "application/json", "Cache-Control": "no-store"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        if response.status not in {200, 201}:
            raise RuntimeError("result_upload_failed")


def main() -> int:
    started = time.monotonic()
    scan_type = os.environ.get("SCAN_TYPE", "")
    input_url = os.environ.get("INPUT_URL", "")
    result_url = os.environ.get("RESULT_URL", "")
    filename = _safe_name(os.environ.get("SOURCE_FILENAME", "artifact"))
    if scan_type not in {"iac", "container"} or not input_url or not result_url:
        return 2
    WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    source = WORK / "artifact"
    try:
        _download(input_url, source)
        findings, scanner_version = _scan(scan_type, source, filename)
        result = {
            "status": "completed",
            "scanner_version": scanner_version,
            "finding_count": len(findings),
            "duration_seconds": min(720, int(time.monotonic() - started)),
            "findings": findings,
        }
        _publish(result, result_url)
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError, json.JSONDecodeError, zipfile.BadZipFile, tarfile.TarError, urllib.error.URLError):
        try:
            _publish({"status": "failed", "error_code": "scanner_execution_failed"}, result_url)
        except Exception:
            pass
        return 1
    finally:
        shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
