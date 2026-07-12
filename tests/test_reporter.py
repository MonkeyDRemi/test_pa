import sys, os, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.reporter import generate_html, generate_markdown
from core.scorer import compute_score
from core.models import Vulnerability


def _sample_vulns():
    return [
        Vulnerability("app.py",  10, 0, "PY_CODE_INJECTION_EVAL", "CRITICAL", "eval() détecté"),
        Vulnerability("app.js",  22, 5, "XSS_INNER_HTML",         "HIGH",     "innerHTML XSS"),
        Vulnerability("app.php",  5, 0, "SQL_INJECTION_CONCAT",   "CRITICAL", "SQL injection"),
    ]


class TestReporter(unittest.TestCase):

    def test_html_report_created(self):
        vulns = _sample_vulns()
        score = compute_score(vulns)
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        generate_html(vulns, score, "./tests", path)
        content = open(path, encoding="utf-8").read()
        self.assertIn("APSA", content)
        self.assertIn("eval() détecté", content)
        self.assertIn("CRITICAL", content)
        self.assertIn(score.grade, content)
        os.unlink(path)

    def test_markdown_report_created(self):
        vulns = _sample_vulns()
        score = compute_score(vulns)
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            path = f.name
        generate_markdown(vulns, score, "./tests", path)
        content = open(path, encoding="utf-8").read()
        self.assertIn("APSA", content)
        self.assertIn("SQL_INJECTION_CONCAT", content)
        self.assertIn("Grade", content)
        os.unlink(path)

    def test_empty_report_no_crash(self):
        score = compute_score([])
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        generate_html([], score, "./tests", path)
        content = open(path, encoding="utf-8").read()
        self.assertIn("APSA", content)
        os.unlink(path)


if __name__ == "__main__":
    unittest.main()
