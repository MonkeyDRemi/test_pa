import sys, os, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.secrets_scanner import scan_text_for_secrets


class TestSecretsScanner(unittest.TestCase):

    def test_aws_access_key_detected(self):
        content = 'key = "AKIAABCDEFGHIJKLMNOP"\n'
        findings = scan_text_for_secrets("f.py", content)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SECRET_AWS_ACCESS_KEY", rule_ids)

    def test_github_token_detected(self):
        content = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"\n'
        findings = scan_text_for_secrets("f.py", content)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SECRET_GITHUB_TOKEN", rule_ids)

    def test_google_api_key_detected(self):
        content = 'GOOGLE_API_KEY = "AIzaSyC8GoiNS73fA1P6SjjqEVcDHivYfjWIyyg"\n'
        findings = scan_text_for_secrets("f.py", content)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SECRET_GOOGLE_API_KEY", rule_ids)

    def test_private_key_block_detected(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIExyz\n-----END RSA PRIVATE KEY-----\n"
        findings = scan_text_for_secrets("f.py", content)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SECRET_PRIVATE_KEY_BLOCK", rule_ids)

    def test_clean_code_no_false_positive(self):
        content = "def add(a, b):\n    return a + b\n"
        findings = scan_text_for_secrets("f.py", content)
        self.assertEqual(findings, [])

    def test_line_number_is_correct(self):
        content = "x = 1\ny = 2\nkey = \"AKIAABCDEFGHIJKLMNOP\"\n"
        findings = scan_text_for_secrets("f.py", content)
        self.assertEqual(findings[0].line, 3)


if __name__ == "__main__":
    unittest.main()
