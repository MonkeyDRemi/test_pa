"""
core/history.py — Historique persistant des scans (SQLite)

Stocke chaque scan effectué (métadonnées + vulnérabilités + conseils IA)
dans une base SQLite locale, pour permettre de consulter, comparer et
re-télécharger les scans passés sans avoir à ré-uploader les fichiers.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from core.models import Vulnerability

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "apsa_history.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id     TEXT PRIMARY KEY,
                scanned_at  TEXT NOT NULL,
                file_count  INTEGER NOT NULL,
                file_names  TEXT NOT NULL,
                total_issues INTEGER NOT NULL,
                score       INTEGER NOT NULL,
                grade       TEXT NOT NULL,
                summary     TEXT NOT NULL,
                by_severity TEXT NOT NULL,
                vulns_json  TEXT NOT NULL,
                ai_advices_json TEXT NOT NULL DEFAULT '{}',
                ai_enabled  INTEGER NOT NULL DEFAULT 0,
                warnings_json TEXT NOT NULL DEFAULT '[]'
            )
        """)
        conn.commit()


def save_scan(
    scan_id: str,
    file_names: list[str],
    vulns: list[Vulnerability],
    score,
    ai_advices: dict,
    ai_enabled: bool,
    warnings: list[str],
) -> None:
    init_db()
    with _connect() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO scans
               (scan_id, scanned_at, file_count, file_names, total_issues,
                score, grade, summary, by_severity, vulns_json,
                ai_advices_json, ai_enabled, warnings_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                datetime.now().isoformat(),
                len(file_names),
                json.dumps(file_names, ensure_ascii=False),
                len(vulns),
                score.score,
                score.grade,
                score.summary,
                json.dumps(score.by_severity, ensure_ascii=False),
                json.dumps([asdict(v) for v in vulns], ensure_ascii=False),
                json.dumps(ai_advices, ensure_ascii=False),
                int(ai_enabled),
                json.dumps(warnings, ensure_ascii=False),
            ),
        )
        conn.commit()


def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    """Retourne la liste des scans, du plus récent au plus ancien (résumé léger)."""
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """SELECT scan_id, scanned_at, file_count, file_names,
                      total_issues, score, grade, summary, by_severity
               FROM scans ORDER BY scanned_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()

    result = []
    for r in rows:
        result.append({
            "scan_id":      r["scan_id"],
            "scanned_at":   datetime.fromisoformat(r["scanned_at"]),
            "file_count":   r["file_count"],
            "file_names":   json.loads(r["file_names"]),
            "total_issues": r["total_issues"],
            "score":        r["score"],
            "grade":        r["grade"],
            "summary":      r["summary"],
            "by_severity":  json.loads(r["by_severity"]),
        })
    return result


def get_scan(scan_id: str) -> dict[str, Any] | None:
    """Récupère un scan complet (vulnérabilités + conseils IA inclus)."""
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()

    if row is None:
        return None

    vulns_raw = json.loads(row["vulns_json"])
    vulns = [Vulnerability(**v) for v in vulns_raw]

    return {
        "scan_id":      row["scan_id"],
        "scanned_at":   datetime.fromisoformat(row["scanned_at"]),
        "file_count":   row["file_count"],
        "file_names":   json.loads(row["file_names"]),
        "vulns":        vulns,
        "score_value":  row["score"],
        "grade":        row["grade"],
        "summary":      row["summary"],
        "by_severity":  json.loads(row["by_severity"]),
        "ai_advices":   json.loads(row["ai_advices_json"]),
        "ai_enabled":   bool(row["ai_enabled"]),
        "warnings":     json.loads(row["warnings_json"]),
    }


def delete_scan(scan_id: str) -> bool:
    init_db()
    with _connect() as conn:
        cur = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.commit()
        return cur.rowcount > 0


def clear_history() -> int:
    init_db()
    with _connect() as conn:
        cur = conn.execute("DELETE FROM scans")
        conn.commit()
        return cur.rowcount


def history_stats() -> dict[str, Any]:
    """Petites stats globales pour un dashboard d'historique."""
    scans = list_scans(limit=1000)
    if not scans:
        return {"total_scans": 0, "total_issues": 0, "avg_score": 0, "trend": []}

    total_issues = sum(s["total_issues"] for s in scans)
    avg_score = round(sum(s["score"] for s in scans) / len(scans), 1)

    # tendance (du plus ancien au plus récent) pour un mini graphique
    trend = [{"date": s["scanned_at"].strftime("%d/%m"), "score": s["score"]}
             for s in reversed(scans[:20])]

    return {
        "total_scans":  len(scans),
        "total_issues": total_issues,
        "avg_score":    avg_score,
        "trend":        trend,
    }
