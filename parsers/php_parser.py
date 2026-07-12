import json
import subprocess
from pathlib import Path

from core.models import Vulnerability

_SCANNER_PHP = Path(__file__).parent / "php_scanner.php"


class PHPScanner:

    def __init__(self, filename: str, config: dict):
        self.filename = filename
        self.config   = config
        self.findings: list[Vulnerability] = []
        self._stderr_msg: str | None = None

    def scan(self) -> list[Vulnerability]:
        self.findings = []
        php_bin = self._find_php()
        if not php_bin:
            raise RuntimeError(
                "PHP introuvable. Installe-le pour activer l'analyse PHP."
            )

        if not _SCANNER_PHP.exists():
            raise FileNotFoundError(
                f"Script scanner PHP manquant : {_SCANNER_PHP}"
            )

        result = subprocess.run(
            [php_bin, str(_SCANNER_PHP), self.filename],
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
                f"Réponse JSON invalide du scanner PHP : {e}\n"
                f"Sortie brute : {result.stdout[:200]}"
            )

        for item in raw:
            self.findings.append(
                Vulnerability(
                    file        = item["file"],
                    line        = item["line"],
                    column      = item["column"],
                    rule_id     = item["rule_id"],
                    severity    = item["severity"],
                    description = item["description"],
                )
            )

        return self.findings

    @staticmethod
    def _find_php() -> str | None:
        import shutil
        return shutil.which("php")
