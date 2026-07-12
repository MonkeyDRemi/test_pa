import ast
from core.models import Vulnerability

_CRITICAL_FUNC_RULES = {
    "eval"      : ("PY_CODE_INJECTION_EVAL",    "CRITICAL"),
    "exec"      : ("PY_CODE_INJECTION_EXEC",    "CRITICAL"),
    "compile"   : ("PY_CODE_INJECTION_COMPILE", "HIGH"),
    "system"    : ("PY_CMD_INJECTION_SYSTEM",   "CRITICAL"),
    "popen"     : ("PY_CMD_INJECTION_POPEN",    "CRITICAL"),
    "subprocess": ("PY_CMD_INJECTION_SUBPROCESS","HIGH"),
    "getoutput" : ("PY_CMD_INJECTION_GETOUTPUT","CRITICAL"),
    "call"      : ("PY_CMD_INJECTION_CALL",     "HIGH"),
    "run"       : ("PY_CMD_INJECTION_RUN",      "HIGH"),
    "Popen"     : ("PY_CMD_INJECTION_POPEN_CLS","HIGH"),
}

_SQL_SINKS = {"execute", "query", "executemany"}


class PythonScanner(ast.NodeVisitor):

    def __init__(self, filename: str, config: dict):
        self.filename = filename
        self.config   = config
        self.findings: list[Vulnerability] = []


    def visit_Call(self, node: ast.Call):
        func_name = self._get_func_name(node)

        config_critical = (
            self.config.get("rules", {})
                       .get("python", {})
                       .get("critical_functions", [])
        )
        if func_name in config_critical or func_name in _CRITICAL_FUNC_RULES:
            rule_id, severity = _CRITICAL_FUNC_RULES.get(
                func_name, ("PY_DANGEROUS_FUNCTION", "HIGH")
            )
            self._add(node, rule_id, severity,
                      f"Fonction dangereuse détectée : {func_name}()")

        if func_name in _SQL_SINKS:
            for arg in node.args:
                if isinstance(arg, (ast.BinOp, ast.JoinedStr)):
                    self._add(node, "PY_SQL_INJECTION", "CRITICAL",
                              "Injection SQL potentielle — requête construite dynamiquement")
                    break

        self.generic_visit(node)


    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name_lower = target.id.lower()
            if any(k in name_lower for k in ("password", "passwd", "secret",
                                              "api_key", "apikey", "token")):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    if len(node.value.value) > 3:
                        self._add(node, "PY_HARDCODED_SECRET", "HIGH",
                                  f"Secret potentiellement codé en dur : {target.id}")
        self.generic_visit(node)


    @staticmethod
    def _get_func_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    def _add(self, node: ast.AST, rule_id: str, severity: str, message: str):
        self.findings.append(Vulnerability(
            file        = self.filename,
            line        = node.lineno,
            column      = node.col_offset,
            rule_id     = rule_id,
            severity    = severity,
            description = message,
        ))
