import sys, os, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.scorer import compute_score
from core.models import Vulnerability


def _make(severity):
    return Vulnerability(file="f.py", line=1, column=0,
                         rule_id="TEST", severity=severity, description="test")


class TestScorer(unittest.TestCase):

    def test_empty_is_grade_a(self):
        score = compute_score([])
        self.assertEqual(score.grade, "A")
        self.assertEqual(score.score, 0)
        self.assertEqual(score.total_issues, 0)

    def test_single_critical(self):
        score = compute_score([_make("CRITICAL")])
        self.assertIn(score.grade, ("B", "C", "D", "F"))
        self.assertGreater(score.score, 0)

    def test_score_capped_at_100(self):
        score = compute_score([_make("CRITICAL")] * 10)
        self.assertLessEqual(score.score, 100)

    def test_severity_weights_ordered(self):
        s_crit = compute_score([_make("CRITICAL")]).score
        s_high = compute_score([_make("HIGH")]).score
        s_med  = compute_score([_make("MEDIUM")]).score
        s_low  = compute_score([_make("LOW")]).score
        self.assertGreater(s_crit, s_high)
        self.assertGreater(s_high, s_med)
        self.assertGreater(s_med,  s_low)

    def test_grade_f_on_many_criticals(self):
        score = compute_score([_make("CRITICAL")] * 5)
        self.assertIn(score.grade, ("D", "F"))

    def test_by_severity_counts(self):
        vulns = [_make("CRITICAL"), _make("CRITICAL"), _make("HIGH"), _make("LOW")]
        score = compute_score(vulns)
        self.assertEqual(score.by_severity["CRITICAL"], 2)
        self.assertEqual(score.by_severity["HIGH"], 1)
        self.assertEqual(score.by_severity["LOW"], 1)


if __name__ == "__main__":
    unittest.main()
