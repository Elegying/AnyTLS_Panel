import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


class RepositoryQualityTests(unittest.TestCase):
    def test_community_health_files_exist(self):
        required = {
            "README.md",
            "CONTRIBUTING.md",
            "CODE_OF_CONDUCT.md",
            "SECURITY.md",
            "SUPPORT.md",
            "LICENSE",
            "CHANGELOG.md",
            ".editorconfig",
            ".github/pull_request_template.md",
            ".github/workflows/codeql.yml",
            ".github/ISSUE_TEMPLATE/bug_report.yml",
            ".github/ISSUE_TEMPLATE/feature_request.yml",
            ".github/ISSUE_TEMPLATE/config.yml",
            "docs/README.md",
            "docs/QUICKSTART.md",
            "docs/CONFIGURATION.md",
            "docs/API.md",
            "docs/ARCHITECTURE.md",
            "docs/FAQ.md",
            "docs/OPERATIONS.md",
            "docs/assets/accounts.jpg",
            "docs/assets/dashboard.jpg",
            "docs/assets/mobile-dashboard.jpg",
            "docs/assets/monitor.jpg",
        }

        missing = sorted(path for path in required if not (REPO_ROOT / path).is_file())
        self.assertEqual(missing, [])

    def test_ci_has_least_privilege_and_cancels_stale_runs(self):
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertIn("workflow_dispatch:", workflow)

    def test_local_markdown_links_resolve(self):
        link_pattern = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
        failures = []
        markdown_files = [
            path
            for path in REPO_ROOT.rglob("*.md")
            if ".git" not in path.parts and path.name != "design-qa.md"
        ]

        for document in markdown_files:
            content = document.read_text(encoding="utf-8")
            for raw_target in link_pattern.findall(content):
                target = raw_target.strip().split()[0].strip("<>")
                if (
                    not target
                    or target.startswith(("http://", "https://", "mailto:", "#"))
                ):
                    continue
                local_path = target.split("#", 1)[0]
                resolved = (document.parent / local_path).resolve()
                if not resolved.exists():
                    failures.append(
                        f"{document.relative_to(REPO_ROOT)} -> {target}"
                    )

        self.assertEqual(failures, [])

    def test_release_manifest_is_unique_and_complete(self):
        entries = [
            line.strip()
            for line in (REPO_ROOT / "release-files.txt").read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

        self.assertEqual(len(entries), len(set(entries)))
        missing = sorted(entry for entry in entries if not (REPO_ROOT / entry).is_file())
        self.assertEqual(missing, [])

    def test_documented_release_matches_deploy_default(self):
        deploy = (REPO_ROOT / "deploy.sh").read_text(encoding="utf-8")
        match = re.search(r'REPO_REF="\$\{ANYTLS_REPO_REF:-(v\d+\.\d+\.\d+)\}"', deploy)
        self.assertIsNotNone(match)
        release = match.group(1)

        for document in (
            "README.md",
            "docs/QUICKSTART.md",
            "docs/OPERATIONS.md",
        ):
            with self.subTest(document=document):
                content = (REPO_ROOT / document).read_text(encoding="utf-8")
                self.assertIn(release, content)


if __name__ == "__main__":
    unittest.main()
