"""
core/dedupe.py — Dédoublonnage des vulnérabilités détectées.

Deux findings sont considérés comme des doublons s'ils portent sur le même
fichier, la même ligne, la même règle et la même description. Cela peut
arriver quand plusieurs scanners (ou plusieurs passes) remontent le même
problème.
"""
from __future__ import annotations
from core.models import Vulnerability


def dedupe_vulnerabilities(
    vulns: list[Vulnerability],
) -> tuple[list[Vulnerability], int]:
    """Retire les doublons exacts. Retourne (liste_dédupliquée, nb_supprimés)."""
    seen: set[tuple] = set()
    kept: list[Vulnerability] = []
    removed = 0

    for v in vulns:
        key = (v.file, v.line, v.rule_id, v.description)
        if key in seen:
            removed += 1
            continue
        seen.add(key)
        kept.append(v)

    return kept, removed
