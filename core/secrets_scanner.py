"""
core/secrets_scanner.py — Détection de secrets par signatures connues.

Contrairement à la détection Python existante (qui regarde si le NOM de la
variable contient "password"/"token"/...), ce module cherche des motifs
*structurels* propres aux formats de clés/tokens réels émis par les grands
fournisseurs. Il est indépendant du langage : on l'applique sur le texte
brut de n'importe quel fichier scanné.
"""
from __future__ import annotations
import re
from core.models import Vulnerability

# Chaque entrée : (rule_id, sévérité, regex compilé, description)
_SECRET_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    ("SECRET_AWS_ACCESS_KEY", "CRITICAL",
     re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
     "Clé d'accès AWS (Access Key ID) codée en dur"),

    ("SECRET_AWS_SECRET_KEY", "CRITICAL",
     re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"),
     "Clé secrète AWS (Secret Access Key) codée en dur"),

    ("SECRET_GITHUB_TOKEN", "CRITICAL",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
     "Token d'accès GitHub codé en dur"),

    ("SECRET_GOOGLE_API_KEY", "HIGH",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
     "Clé API Google codée en dur"),

    ("SECRET_SLACK_TOKEN", "CRITICAL",
     re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"),
     "Token Slack codé en dur"),

    ("SECRET_SLACK_WEBHOOK", "HIGH",
     re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
     "URL de webhook Slack codée en dur"),

    ("SECRET_STRIPE_KEY", "CRITICAL",
     re.compile(r"\bsk_live_[0-9a-zA-Z]{16,64}\b"),
     "Clé secrète Stripe (mode live) codée en dur"),

    ("SECRET_PRIVATE_KEY_BLOCK", "CRITICAL",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     "Bloc de clé privée (PEM) codé en dur"),

    ("SECRET_GENERIC_JWT", "MEDIUM",
     re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     "Jeton JWT codé en dur"),
]


def scan_text_for_secrets(filepath: str, content: str) -> list[Vulnerability]:
    """Scanne le contenu brut d'un fichier ligne par ligne, tous langages confondus."""
    findings: list[Vulnerability] = []

    for lineno, line in enumerate(content.splitlines(), start=1):
        for rule_id, severity, pattern, message in _SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(Vulnerability(
                    file=filepath,
                    line=lineno,
                    column=0,
                    rule_id=rule_id,
                    severity=severity,
                    description=message,
                ))

    return findings
