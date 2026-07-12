import ast, sys, os, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from parsers.py_parser import PythonScanner


def _scan(code):
    tree = ast.parse(code)
    scanner = PythonScanner("<test>", {})
    scanner.visit(tree)
    return scanner.findings

def _rule_ids(code):
    return {f.rule_id for f in _scan(code)}


class TestPythonScanner(unittest.TestCase):

    def test_eval_detected(self):
        self.assertIn("PY_CODE_INJECTION_EVAL", _rule_ids("eval(user_input)"))

    def test_exec_detected(self):
        self.assertIn("PY_CODE_INJECTION_EXEC", _rule_ids("exec(user_input)"))

    def test_os_system_detected(self):
        self.assertIn("PY_CMD_INJECTION_SYSTEM", _rule_ids("os.system(cmd)"))

    def test_popen_detected(self):
        self.assertIn("PY_CMD_INJECTION_POPEN", _rule_ids("os.popen(cmd)"))

    def test_sql_injection_concat(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        self.assertIn("PY_SQL_INJECTION", _rule_ids(code))

    def test_sql_injection_fstring(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        self.assertIn("PY_SQL_INJECTION", _rule_ids(code))

    def test_sql_safe_static(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))'
        self.assertNotIn("PY_SQL_INJECTION", _rule_ids(code))

    def test_hardcoded_password(self):
        self.assertIn("PY_HARDCODED_SECRET", _rule_ids('password = "super_secret_123"'))

    def test_hardcoded_api_key(self):
        self.assertIn("PY_HARDCODED_SECRET", _rule_ids('api_key = "AIzaSyABC123"'))

    def test_short_value_not_flagged(self):
        self.assertNotIn("PY_HARDCODED_SECRET", _rule_ids('password = "ok"'))

    def test_vulnerability_fields(self):
        findings = _scan("eval(x)")
        self.assertGreaterEqual(len(findings), 1)
        v = findings[0]
        self.assertEqual(v.file, "<test>")
        self.assertGreaterEqual(v.line, 1)
        self.assertIn(v.severity, ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        self.assertNotEqual(v.rule_id, "")

    def test_no_false_positive_clean_code(self):
        code = "def add(a, b):\n    return a + b\nresult = add(1, 2)\nprint(result)\n"
        self.assertEqual(_scan(code), [])


if __name__ == "__main__":
    unittest.main()
