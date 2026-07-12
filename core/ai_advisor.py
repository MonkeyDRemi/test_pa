from __future__ import annotations
import os
import json
import time
from dataclasses import dataclass
from core.models import Vulnerability

try:
    from google import genai
    _GENAI_AVAILABLE = True
except ImportError:
    _GENAI_AVAILABLE = False


_SYSTEM_PROMPT = """Tu es un expert en sécurité applicative (SAST/OWASP).
On te donne une vulnérabilité détectée dans du code source.
Réponds UNIQUEMENT en JSON valide avec exactement ces 3 clés :
{
  "explication": "explication claire du risque en 2-3 phrases, en français",
  "impact": "conséquence concrète si exploitée (ex: vol de données, RCE...)",
  "fix": "extrait de code corrigé avec commentaire explicatif"
}
Sois concis et pratique. Le fix doit être dans le même langage que le fichier source.
IMPORTANT: dans le champ fix, n'utilise pas de backslash seul dans les chaînes JSON."""

_DELAY_SECONDS = 13


@dataclass
class AIAdvice:
    rule_id    : str
    explication: str
    impact     : str
    fix        : str
    error      : str | None = None


def get_advice(vuln: Vulnerability) -> AIAdvice:
    if not _GENAI_AVAILABLE:
        return AIAdvice(rule_id=vuln.rule_id, explication="", impact="", fix="",
                        error="Module google-genai non installé. Lance : pip install google-genai")

    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        return AIAdvice(rule_id=vuln.rule_id, explication="", impact="", fix="",
                        error="Variable d'environnement GOOGLE_API_KEY manquante")

    try:
        client = genai.Client(api_key=api_key)

        ext = vuln.file.rsplit(".", 1)[-1] if "." in vuln.file else "?"
        prompt = (
            f"{_SYSTEM_PROMPT}\n\n"
            f"Fichier : {vuln.file} (langage : {ext})\n"
            f"Ligne   : {vuln.line}\n"
            f"Règle   : {vuln.rule_id}\n"
            f"Message : {vuln.description}\n\n"
            f"Analyse cette vulnérabilité et fournis le JSON demandé."
        )

        response = client.models.generate_content(
            model="gemini-3.1-flash-lite",
            contents=prompt,
        )

        text = response.text.strip()

        if text.startswith("```"):
            text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()

        parsed = json.loads(text)
        return AIAdvice(
            rule_id     = vuln.rule_id,
            explication = parsed.get("explication", ""),
            impact      = parsed.get("impact", ""),
            fix         = parsed.get("fix", ""),
        )

    except json.JSONDecodeError as e:
        return AIAdvice(rule_id=vuln.rule_id, explication="", impact="", fix="",
                        error=f"Réponse JSON invalide : {e}")
    except Exception as e:
        return AIAdvice(rule_id=vuln.rule_id, explication="", impact="", fix="",
                        error=str(e))


def enrich_vulnerabilities(
    vulnerabilities: list[Vulnerability],
    max_calls: int = 40,
) -> dict[str, AIAdvice]:
    """
    Enrichit les N premiers types de vulnérabilités uniques (par rule_id).
    Déduplique par rule_id pour éviter des appels identiques.
    Ajoute un délai entre les appels pour respecter le rate limit gratuit.
    Retourne un dict { rule_id: AIAdvice }.
    """
    seen    : set[str]            = set()
    advices : dict[str, AIAdvice] = {}

    for vuln in vulnerabilities:
        if len(advices) >= max_calls:
            break
        if vuln.rule_id in seen:
            continue
        seen.add(vuln.rule_id)

        if advices:
            time.sleep(_DELAY_SECONDS)

        advices[vuln.rule_id] = get_advice(vuln)

    return advices
