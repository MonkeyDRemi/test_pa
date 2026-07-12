import sys, os, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.dedupe import dedupe_vulnerabilities
from core.models import Vulnerability


def _make(rule_id="RULE", line=1, desc="desc"):
    return Vulnerability(file="f.py", line=line, column=0,
                         rule_id=rule_id, severity="HIGH", description=desc)


class TestDedupe(unittest.TestCase):

    def test_exact_duplicates_removed(self):
        vulns = [_make(), _make()]
        kept, removed = dedupe_vulnerabilities(vulns)
        self.assertEqual(len(kept), 1)
        self.assertEqual(removed, 1)

    def test_different_lines_kept(self):
        vulns = [_make(line=1), _make(line=2)]
        kept, removed = dedupe_vulnerabilities(vulns)
        self.assertEqual(len(kept), 2)
        self.assertEqual(removed, 0)

    def test_different_rules_same_line_kept(self):
        vulns = [_make(rule_id="A"), _make(rule_id="B")]
        kept, removed = dedupe_vulnerabilities(vulns)
        self.assertEqual(len(kept), 2)

    def test_empty_list(self):
        kept, removed = dedupe_vulnerabilities([])
        self.assertEqual(kept, [])
        self.assertEqual(removed, 0)


if __name__ == "__main__":
    unittest.main()
