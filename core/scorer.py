from dataclasses import dataclass
from collections import Counter
from core.models import Vulnerability

_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH"    : 10,
    "MEDIUM"  :  4,
    "LOW"     :  1,
}

_MAX_RAW = 100


@dataclass
class ScanScore:
    total_issues  : int
    by_severity   : dict[str, int]
    raw_score     : int
    score         : int
    grade         : str
    summary       : str

    @property
    def color(self) -> str:
        return {
            "A": "green",
            "B": "yellow",
            "C": "orange3",
            "D": "red",
            "F": "bold red",
        }.get(self.grade, "white")


def compute_score(vulnerabilities: list[Vulnerability]) -> ScanScore:
    by_severity: dict[str, int] = Counter(v.severity for v in vulnerabilities)

    raw = sum(
        _WEIGHTS.get(sev, 0) * count
        for sev, count in by_severity.items()
    )
    score = min(raw, _MAX_RAW)

    if score == 0:
        grade, summary = "A", "Aucune vulnérabilité détectée — code propre ✅"
    elif score <= 10:
        grade, summary = "B", "Risque faible — quelques points mineurs à corriger"
    elif score <= 30:
        grade, summary = "C", "Risque modéré — des corrections sont recommandées"
    elif score <= 60:
        grade, summary = "D", "Risque élevé — plusieurs failles critiques à traiter en priorité"
    else:
        grade, summary = "F", "Risque critique — le code présente des vulnérabilités sévères"

    return ScanScore(
        total_issues = len(vulnerabilities),
        by_severity  = dict(by_severity),
        raw_score    = raw,
        score        = score,
        grade        = grade,
        summary      = summary,
    )
