import sys, os, unittest, tempfile, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pathlib import Path
from core.sca_scanner import _parse_requirements_txt, _parse_package_json


class TestSCAParsing(unittest.TestCase):

    def test_parse_requirements_pinned(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("flask==2.0.1\n# comment\nrequests==2.25.0\nunpinned-package\n")
        deps = _parse_requirements_txt(Path(path))
        names = {d[0] for d in deps}
        self.assertIn("flask", names)
        self.assertIn("requests", names)
        self.assertEqual(len(deps), 2)  # "unpinned-package" ignoré (pas de ==)
        os.remove(path)

    def test_parse_requirements_empty_file(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("\n# only comments\n")
        deps = _parse_requirements_txt(Path(path))
        self.assertEqual(deps, [])
        os.remove(path)

    def test_parse_package_json(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        pkg = {
            "dependencies": {"express": "^4.18.2", "lodash": "4.17.21"},
            "devDependencies": {"jest": "~29.0.0"},
        }
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(pkg))
        deps = _parse_package_json(Path(path))
        names_versions = {(d[0], d[1]) for d in deps}
        self.assertIn(("express", "4.18.2"), names_versions)
        self.assertIn(("lodash", "4.17.21"), names_versions)
        self.assertIn(("jest", "29.0.0"), names_versions)
        os.remove(path)

    def test_parse_package_json_invalid(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write("{not valid json")
        deps = _parse_package_json(Path(path))
        self.assertEqual(deps, [])
        os.remove(path)


if __name__ == "__main__":
    unittest.main()
