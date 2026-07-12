"""
web_app.py — Couche web Flask pour APSA SAST
Ajoute une interface web par-dessus le code CLI existant, sans le modifier.
"""
from __future__ import annotations

import ast
import os
import shutil
import tempfile
import threading
import uuid
from pathlib import Path
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    jsonify,
    send_file,
)
import yaml

# ── Core APSA (inchangé) ──────────────────────────────────────────────────────
from core.models import Vulnerability
from core.scorer import compute_score
from core.reporter import generate_html, generate_markdown
from core.dedupe import dedupe_vulnerabilities
from core.suppressions import filter_suppressed
from core.secrets_scanner import scan_text_for_secrets
from core.sca_scanner import scan_dependencies
from parsers.py_parser import PythonScanner
from parsers.js_parser import JavaScriptScanner
from parsers.php_parser import PHPScanner
from core import history

# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "apsa-dev-secret-change-in-prod")

@app.template_filter("basename")
def basename_filter(path):
    return Path(str(path)).name

_SCANS: dict[str, dict] = {}
_SCANS_LOCK = threading.Lock()

UPLOAD_FOLDER = Path(tempfile.gettempdir()) / "apsa_uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {".py", ".js", ".php"}
ALLOWED_MANIFESTS = {"requirements.txt", "package.json"}


def _is_allowed_upload(filename: str) -> bool:
    return Path(filename).suffix in ALLOWED_EXTENSIONS or filename in ALLOWED_MANIFESTS

# Clé Gemini configurée côté serveur (variable d'environnement Render).
# Si présente, le champ web n'est utilisé qu'en fallback / override.
SERVER_GEMINI_KEY = os.environ.get("GOOGLE_API_KEY", "").strip()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_config(config_path: str = "config.yaml") -> dict:
    try:
        with open(config_path, "r", encoding="utf-8-sig") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def _scan_directory(target_path: Path, config: dict) -> tuple[list[Vulnerability], list[str]]:
    """Réutilise la logique de main.py. Retourne (vulns, warnings)."""
    all_vulns: list[Vulnerability] = []
    warnings:  list[str]           = []

    for fp in target_path.rglob("*.py"):
        try:
            with open(fp, "r", encoding="utf-8-sig", errors="ignore") as f:
                content = f.read()
            tree = ast.parse(content)
            scanner = PythonScanner(str(fp), config)
            scanner.visit(tree)
            all_vulns.extend(scanner.findings)
            all_vulns.extend(scan_text_for_secrets(str(fp), content))
        except SyntaxError as e:
            warnings.append(f"Syntaxe Python invalide dans {fp.name} : {e}")
        except Exception as e:
            warnings.append(f"Erreur Python {fp.name} : {e}")

    for fp in target_path.rglob("*.js"):
        try:
            scanner = JavaScriptScanner(str(fp), config)
            findings = scanner.scan()
            if getattr(scanner, "_stderr_msg", None):
                warnings.append(f"JS {fp.name} : {scanner._stderr_msg}")
            all_vulns.extend(findings)
            with open(fp, "r", encoding="utf-8-sig", errors="ignore") as f:
                all_vulns.extend(scan_text_for_secrets(str(fp), f.read()))
        except Exception as e:
            warnings.append(f"Erreur JS {fp.name} : {e} (node.js installé ?)")

    for fp in target_path.rglob("*.php"):
        try:
            scanner = PHPScanner(str(fp), config)
            findings = scanner.scan()
            if getattr(scanner, "_stderr_msg", None):
                warnings.append(f"PHP {fp.name} : {scanner._stderr_msg}")
            all_vulns.extend(findings)
            with open(fp, "r", encoding="utf-8-sig", errors="ignore") as f:
                all_vulns.extend(scan_text_for_secrets(str(fp), f.read()))
        except Exception as e:
            warnings.append(f"Erreur PHP {fp.name} : {e} (php CLI installé ?)")

    # ── SCA : requirements.txt / package.json (CVE via OSV.dev) ─────────────
    try:
        sca_vulns = scan_dependencies(target_path)
        if sca_vulns:
            warnings.append(f"📦 {len(sca_vulns)} vulnérabilité(s) de dépendance(s) trouvée(s) (OSV.dev)")
        all_vulns.extend(sca_vulns)
    except Exception as e:
        warnings.append(f"Scan de dépendances (SCA) indisponible : {e}")

    # ── Dédoublonnage ─────────────────────────────────────────────────────────
    all_vulns, dup_count = dedupe_vulnerabilities(all_vulns)
    if dup_count:
        warnings.append(f"🧹 {dup_count} doublon(s) supprimé(s)")

    # ── Whitelist via `apsa-ignore` ─────────────────────────────────────────
    all_vulns, ignored_count = filter_suppressed(all_vulns)
    if ignored_count:
        warnings.append(f"🙈 {ignored_count} finding(s) ignoré(s) via `apsa-ignore`")

    return all_vulns, warnings


def _severity_order(s: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(s, 9)


def _run_ai(vulns: list[Vulnerability], gemini_key: str, max_ai: int) -> dict:
    """Lance enrich_vulnerabilities en arrière-plan si clé fournie."""
    os.environ["GOOGLE_API_KEY"] = gemini_key
    from core.ai_advisor import enrich_vulnerabilities
    return enrich_vulnerabilities(vulns, max_calls=max_ai)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", server_key_configured=bool(SERVER_GEMINI_KEY))


@app.route("/scan", methods=["POST"])
def scan():
    uploaded_files = request.files.getlist("files")
    if not uploaded_files or all(f.filename == "" for f in uploaded_files):
        return render_template("index.html", error="Aucun fichier sélectionné.",
                                server_key_configured=bool(SERVER_GEMINI_KEY))

    use_ai       = request.form.get("use_ai") == "on"
    max_ai       = int(request.form.get("max_ai", 10))

    # Seule la clé configurée côté serveur (variable d'environnement) est utilisée.
    # Aucune clé ne peut être fournie par le client (sécurité).
    gemini_key = SERVER_GEMINI_KEY

    scan_id  = uuid.uuid4().hex
    scan_dir = UPLOAD_FOLDER / scan_id
    scan_dir.mkdir(parents=True)

    saved = 0
    file_names: list[str] = []
    for f in uploaded_files:
        if f and _is_allowed_upload(f.filename):
            dest = scan_dir / Path(f.filename).name
            f.save(dest)
            file_names.append(Path(f.filename).name)
            saved += 1

    if saved == 0:
        shutil.rmtree(scan_dir, ignore_errors=True)
        return render_template("index.html",
                               error="Aucun fichier .py / .js / .php valide uploadé.",
                               server_key_configured=bool(SERVER_GEMINI_KEY))

    config = _load_config()
    vulns, warnings = _scan_directory(scan_dir, config)
    score = compute_score(vulns)
    vulns_sorted = sorted(vulns, key=lambda v: (_severity_order(v.severity), v.file, v.line))

    # ── Analyse IA (synchrone, bloquant) ──────────────────────────────────────
    ai_advices: dict = {}
    ai_error:   str  = ""
    ai_used = bool(use_ai and gemini_key and vulns)

    if use_ai and not gemini_key:
        ai_error = "Analyse IA indisponible : clé non configurée côté serveur."
    elif ai_used:
        try:
            ai_advices = _run_ai(vulns_sorted, gemini_key, max_ai)
        except Exception as e:
            ai_error = str(e)

    result = {
        "scan_id":    scan_id,
        "target":     scan_dir,
        "vulns":      vulns_sorted,
        "score":      score,
        "file_count": saved,
        "scanned_at": datetime.now().strftime("%d/%m/%Y %H:%M"),
        "warnings":   warnings,
        "ai_advices": ai_advices,
        "ai_error":   ai_error,
        "ai_enabled": ai_used,
    }

    with _SCANS_LOCK:
        _SCANS[scan_id] = result

    # Persistance dans l'historique (SQLite)
    try:
        history.save_scan(
            scan_id=scan_id,
            file_names=file_names,
            vulns=vulns_sorted,
            score=score,
            ai_advices=ai_advices,
            ai_enabled=ai_used,
            warnings=warnings,
        )
    except Exception:
        pass  # l'historique ne doit jamais faire échouer un scan

    return redirect(url_for("results", scan_id=scan_id))


@app.route("/results/<scan_id>")
def results(scan_id: str):
    with _SCANS_LOCK:
        data = _SCANS.get(scan_id)

    if data is None:
        # Fallback : le scan n'est plus en mémoire (redémarrage serveur) → on
        # tente de le recharger depuis l'historique persistant.
        past = history.get_scan(scan_id)
        if past is None:
            return render_template("error.html",
                                   message="Résultats introuvables ou session expirée."), 404
        data = {
            "scan_id":    past["scan_id"],
            "target":     ", ".join(past["file_names"]),
            "vulns":      past["vulns"],
            "score":      type("S", (), {
                "score": past["score_value"], "grade": past["grade"],
                "summary": past["summary"], "by_severity": past["by_severity"],
            })(),
            "file_count": past["file_count"],
            "scanned_at": past["scanned_at"].strftime("%d/%m/%Y %H:%M"),
            "warnings":   past["warnings"],
            "ai_advices": past["ai_advices"],
            "ai_error":   "",
            "ai_enabled": past["ai_enabled"],
        }

    return render_template("results.html", **data)


@app.route("/download/<scan_id>/<fmt>")
def download(scan_id: str, fmt: str):
    with _SCANS_LOCK:
        data = _SCANS.get(scan_id)
    if data is None:
        return "Scan introuvable", 404
    if fmt not in ("html", "md"):
        return "Format invalide", 400

    out_dir = UPLOAD_FOLDER / scan_id
    if fmt == "html":
        out_path = str(out_dir / "report.html")
        generate_html(data["vulns"], data["score"], str(data["target"]),
                      out_path, ai_advices=data.get("ai_advices", {}))
        return send_file(out_path, as_attachment=True, download_name="rapport_apsa.html")
    else:
        out_path = str(out_dir / "report.md")
        generate_markdown(data["vulns"], data["score"], str(data["target"]),
                          out_path, ai_advices=data.get("ai_advices", {}))
        return send_file(out_path, as_attachment=True, download_name="rapport_apsa.md")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Endpoint JSON — CI/CD friendly."""
    uploaded_files = request.files.getlist("files")
    if not uploaded_files:
        return jsonify({"error": "Aucun fichier"}), 400

    scan_id  = uuid.uuid4().hex
    scan_dir = UPLOAD_FOLDER / scan_id
    scan_dir.mkdir(parents=True)

    for f in uploaded_files:
        if f and _is_allowed_upload(f.filename):
            f.save(scan_dir / Path(f.filename).name)

    config = _load_config()
    vulns, warnings = _scan_directory(scan_dir, config)
    score = compute_score(vulns)

    return jsonify({
        "scan_id":  scan_id,
        "total":    len(vulns),
        "score":    score.score,
        "grade":    score.grade,
        "warnings": warnings,
        "vulnerabilities": [
            {
                "file":        Path(v.file).name,
                "line":        v.line,
                "severity":    v.severity,
                "rule_id":     v.rule_id,
                "description": v.description,
            }
            for v in vulns
        ],
    })


# ── Historique ────────────────────────────────────────────────────────────────

@app.route("/history")
def history_page():
    scans = history.list_scans(limit=50)
    stats = history.history_stats()
    return render_template("history.html", scans=scans, stats=stats)


@app.route("/history/<scan_id>/delete", methods=["POST"])
def history_delete(scan_id: str):
    history.delete_scan(scan_id)
    return redirect(url_for("history_page"))


@app.route("/history/clear", methods=["POST"])
def history_clear():
    history.clear_history()
    return redirect(url_for("history_page"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
