import json
import os
import subprocess
from pathlib import Path

from core.models import Vulnerability

_SCANNER_JS = Path(__file__).parent / "js_scanner.js"


class JavaScriptScanner:

    def __init__(self, filename: str, config: dict):
        self.filename = filename
        self.config   = config
        self.findings: list[Vulnerability] = []

    def scan(self) -> list[Vulnerability]:
        self.findings = []
        node_bin = self._find_node()
        if not node_bin:
            raise RuntimeError(
                "Node.js introuvable. Installe-le pour activer l'analyse JavaScript."
            )

        if not _SCANNER_JS.exists():
            raise FileNotFoundError(
                f"Script scanner JS manquant : {_SCANNER_JS}"
            )

        result = subprocess.run(
            [node_bin, str(_SCANNER_JS), self.filename],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
        )

        if result.stderr:
            self._stderr_msg = result.stderr.strip()
        else:
            self._stderr_msg = None

        if not result.stdout.strip():
            return self.findings

        try:
            raw = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Réponse JSON invalide du scanner JS : {e}\n"
                f"Sortie brute : {result.stdout[:200]}"
            )

        for item in raw:
            self.findings.append(
                Vulnerability(
                    file       = item["file"],
                    line       = item["line"],
                    column     = item["column"],
                    rule_id    = item["rule_id"],
                    severity   = item["severity"],
                    description= item["description"],
                )
            )

        return self.findings


    @staticmethod
    def _find_node() -> str | None:
        candidates = ["node", "nodejs"]
        for name in candidates:
            path = _which(name)
            if path:
                return path
        return None


def _which(name: str) -> str | None:
    import shutil
    return shutil.which(name)
