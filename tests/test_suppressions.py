import sys, os, unittest, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.suppressions import filter_suppressed, is_suppressed
from core.models import Vulnerability


def _write_temp(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    return path


class TestSuppressions(unittest.TestCase):

    def test_line_without_marker_not_suppressed(self):
        path = _write_temp("eval(x)\n")
        v = Vulnerability(file=path, line=1, column=0,
                          rule_id="PY_CODE_INJECTION_EVAL", severity="CRITICAL", description="d")
        self.assertFalse(is_suppressed(v))
        os.remove(path)

    def test_bare_marker_suppresses_any_rule(self):
        path = _write_temp("eval(x)  # apsa-ignore\n")
        v = Vulnerability(file=path, line=1, column=0,
                          rule_id="PY_CODE_INJECTION_EVAL", severity="CRITICAL", description="d")
        self.assertTrue(is_suppressed(v))
        os.remove(path)

    def test_scoped_marker_matches_rule(self):
        path = _write_temp("eval(x)  # apsa-ignore: PY_CODE_INJECTION_EVAL\n")
        v = Vulnerability(file=path, line=1, column=0,
                          rule_id="PY_CODE_INJECTION_EVAL", severity="CRITICAL", description="d")
        self.assertTrue(is_suppressed(v))
        os.remove(path)

    def test_scoped_marker_does_not_match_other_rule(self):
        path = _write_temp("eval(x)  # apsa-ignore: PY_HARDCODED_SECRET\n")
        v = Vulnerability(file=path, line=1, column=0,
                          rule_id="PY_CODE_INJECTION_EVAL", severity="CRITICAL", description="d")
        self.assertFalse(is_suppressed(v))
        os.remove(path)

    def test_filter_suppressed_counts(self):
        path = _write_temp("eval(x)  # apsa-ignore\nexec(y)\n")
        vulns = [
            Vulnerability(file=path, line=1, column=0,
                         rule_id="PY_CODE_INJECTION_EVAL", severity="CRITICAL", description="d"),
            Vulnerability(file=path, line=2, column=0,
                         rule_id="PY_CODE_INJECTION_EXEC", severity="CRITICAL", description="d"),
        ]
        kept, ignored = filter_suppressed(vulns)
        self.assertEqual(len(kept), 1)
        self.assertEqual(ignored, 1)
        self.assertEqual(kept[0].rule_id, "PY_CODE_INJECTION_EXEC")
        os.remove(path)


if __name__ == "__main__":
    unittest.main()
