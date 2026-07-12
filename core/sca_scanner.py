"""
core/sca_scanner.py — Software Composition Analysis (SCA).

Détecte les CVE connues dans les dépendances déclarées via :
  - requirements.txt (pip / PyPI)   — uniquement les pins exacts "nom==version"
  - package.json     (npm)          — dependencies + devDependencies

S'appuie sur l'API publique OSV.dev (https://osv.dev), qui agrège
notamment les advisories GitHub, PyPA, npm et NVD. Aucune clé API requise.

Ce module utilise uniquement la bibliothèque standard (urllib) pour éviter
d'ajouter une dépendance externe au projet.
"""
from __future__ import annotations
import json
import re
import urllib.request
import urllib.error
from pathlib import Path
from core.models import Vulnerability

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL  = "https://api.osv.dev/v1/vulns/{id}"
_REQUEST_TIMEOUT = 15  # secondes

_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)")


# ── Parsing des manifestes ───────────────────────────────────────────────────

def _parse_requirements_txt(path: Path) -> list[tuple[str, str, int]]:
    """Retourne [(nom, version, ligne)] — ne traite que les pins exacts `==`."""
    deps: list[tuple[str, str, int]] = []
    try:
        with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
            for lineno, raw_line in enumerate(f, start=1):
                line = raw_line.split("#", 1)[0].strip()
                if not line:
                    continue
                m = _REQ_LINE_RE.match(line)
                if m:
                    deps.append((m.group(1), m.group(2), lineno))
    except OSError:
        pass
    return deps


def _parse_package_json(path: Path) -> list[tuple[str, str, int]]:
    """Retourne [(nom, version, ligne)] pour dependencies + devDependencies."""
    deps: list[tuple[str, str, int]] = []
    try:
        with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
            raw = f.read()
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return deps

    lines = raw.splitlines()

    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            clean_version = re.sub(r"^[^\d]*", "", str(version))  # retire ^ ~ >= etc.
            if not clean_version:
                continue
            lineno = 1
            for i, l in enumerate(lines, start=1):
                if f'"{name}"' in l:
                    lineno = i
                    break
            deps.append((name, clean_version, lineno))
    return deps


# ── Requête OSV ──────────────────────────────────────────────────────────────

def _query_osv_batch(
    deps: list[tuple[str, str, int]], ecosystem: str
) -> dict[tuple[str, str], list[str]]:
    """
    Interroge /v1/querybatch en une seule requête.
    ATTENTION : cet endpoint ne renvoie que des IDs de vulnérabilités
    (pas de résumé/sévérité) — voir https://google.github.io/osv.dev/post-v1-querybatch/
    Retourne {(nom, version): [vuln_id, ...]}.
    """
    if not deps:
        return {}

    body = json.dumps({
        "queries": [
            {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
            for name, version, _ in deps
        ]
    }).encode("utf-8")

    req = urllib.request.Request(
        OSV_BATCH_URL, data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        # Pas de réseau, timeout, ou API indisponible → on ne bloque pas le scan
        return {}

    results: dict[tuple[str, str], list[str]] = {}
    for (name, version, _), entry in zip(deps, data.get("results", [])):
        ids = [v["id"] for v in entry.get("vulns", []) if "id" in v]
        if ids:
            results[(name, version)] = ids
    return results


def _fetch_vuln_details(vuln_ids: set[str]) -> dict[str, dict]:
    """Récupère le détail complet (résumé, sévérité) de chaque ID via GET /v1/vulns/{id}."""
    details: dict[str, dict] = {}
    for vuln_id in vuln_ids:
        try:
            req = urllib.request.Request(OSV_VULN_URL.format(id=vuln_id))
            with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
                details[vuln_id] = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            details[vuln_id] = {}
    return details


def _severity_from_osv(vuln: dict) -> str:
    db_severity = (vuln.get("database_specific", {}) or {}).get("severity", "")
    if db_severity:
        return _SEVERITY_MAP.get(db_severity.upper(), "HIGH")
    # Pas de sévérité structurée fournie par l'advisory → HIGH par défaut,
    # car une CVE connue et non patchée reste un risque significatif.
    return "HIGH"


def _scan_manifest(path: Path, ecosystem: str, parser) -> list[Vulnerability]:
    deps = parser(path)
    if not deps:
        return []

    osv_ids_by_dep = _query_osv_batch(deps, ecosystem)
    all_ids = {vid for ids in osv_ids_by_dep.values() for vid in ids}
    vuln_details = _fetch_vuln_details(all_ids)

    findings: list[Vulnerability] = []
    for name, version, lineno in deps:
        for vuln_id in osv_ids_by_dep.get((name, version), []):
            vuln    = vuln_details.get(vuln_id, {})
            summary = vuln.get("summary") or (vuln.get("details") or "")[:200]
            summary = summary or "Vulnérabilité connue référencée dans OSV.dev"
            findings.append(Vulnerability(
                file=str(path),
                line=lineno,
                column=0,
                rule_id=f"SCA_{vuln_id}",
                severity=_severity_from_osv(vuln),
                description=f"{name}=={version} — {vuln_id} : {summary}",
            ))

    return findings


def scan_dependencies(target_path: Path) -> list[Vulnerability]:
    """Point d'entrée : scanne requirements.txt et package.json sous target_path."""
    findings: list[Vulnerability] = []

    for fp in target_path.rglob("requirements.txt"):
        findings.extend(_scan_manifest(fp, "PyPI", _parse_requirements_txt))

    for fp in target_path.rglob("package.json"):
        findings.extend(_scan_manifest(fp, "npm", _parse_package_json))

    return findings
