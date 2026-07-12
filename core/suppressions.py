"""
core/suppressions.py — Whitelist de faux positifs via commentaire en ligne.

Fonctionne pour Python (#), JavaScript/PHP (// ou /* */) car on ne cherche
que la présence du marqueur dans le texte brut de la ligne, peu importe la
syntaxe de commentaire utilisée par le langage.

Usage dans le code scanné :

    eval(user_input)  # apsa-ignore
    eval(user_input)  // apsa-ignore
    eval(user_input)  # apsa-ignore: PY_CODE_INJECTION_EVAL

- `apsa-ignore` seul  → ignore TOUTES les règles sur cette ligne.
- `apsa-ignore: RULE1,RULE2` → n'ignore que les règles listées (utile si
  plusieurs findings tombent sur la même ligne).
"""
from __future__ import annotations
import re
from core.models import Vulnerability

_IGNORE_RE = re.compile(r"apsa-ignore(?:\s*:\s*([A-Za-z0-9_,\s]+))?", re.IGNORECASE)

# Cache des lignes de fichiers pour éviter de relire un fichier N fois
# quand il a plusieurs findings.
_lines_cache: dict[str, list[str]] = {}


def _get_lines(filepath: str) -> list[str]:
    if filepath not in _lines_cache:
        try:
            with open(filepath, "r", encoding="utf-8-sig", errors="ignore") as f:
                _lines_cache[filepath] = f.readlines()
        except OSError:
            _lines_cache[filepath] = []
    return _lines_cache[filepath]


def is_suppressed(v: Vulnerability) -> bool:
    """Vrai si la ligne du finding contient un marqueur apsa-ignore qui le couvre."""
    lines = _get_lines(v.file)
    if not (1 <= v.line <= len(lines)):
        return False

    match = _IGNORE_RE.search(lines[v.line - 1])
    if not match:
        return False

    rules_str = match.group(1)
    if not rules_str:
        return True  # apsa-ignore sans précision → toutes les règles de la ligne

    rules = {r.strip().upper() for r in rules_str.split(",") if r.strip()}
    return v.rule_id.upper() in rules


def filter_suppressed(vulns: list[Vulnerability]) -> tuple[list[Vulnerability], int]:
    """Retire les vulnérabilités marquées `apsa-ignore`. Retourne (liste, nb_ignorés)."""
    kept: list[Vulnerability] = []
    ignored = 0

    for v in vulns:
        if is_suppressed(v):
            ignored += 1
        else:
            kept.append(v)

    _lines_cache.clear()
    return kept, ignored
