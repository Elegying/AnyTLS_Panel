"""Vendor fallback must never install unauthenticated package bytes."""
import pathlib
import subprocess
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'deploy.sh'


class CaddyFallbackTests(unittest.TestCase):
    def run_shell(self, body):
        return subprocess.run(['bash', '-c', f'source "{SCRIPT}"; ' + body],
                              capture_output=True, text=True)

    def test_repository_error_upgrades_through_verified_fallback(self):
        result = self.run_shell('''
            UPGRADED=0
            caddy() { :; }
            systemctl() { return 0; }
            caddy_version_is_supported() { [[ "$UPGRADED" == 1 ]]; }
            install_caddy_from_official_repository() { return 1; }
            install_caddy_from_verified_release() { UPGRADED=1; echo verified-fallback; }
            ensure_caddy
            [[ "$CADDY_INSTALL_ATTEMPTED" == 1 && "$CADDY_INSTALLED_NOW" == 0 ]]
        ''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('verified-fallback', result.stdout)

    def test_outdated_repository_result_also_uses_fallback(self):
        result = self.run_shell('''
            UPGRADED=0
            caddy() { :; }
            systemctl() { return 0; }
            caddy_version_is_supported() { [[ "$UPGRADED" == 1 ]]; }
            install_caddy_from_official_repository() { return 0; }
            install_caddy_from_verified_release() { UPGRADED=1; }
            ensure_caddy
        ''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_checksum_failure_never_runs_package_scripts(self):
        result = self.run_shell('''
            dpkg() { if [[ "$1" == --print-architecture ]]; then echo amd64; else echo UNSAFE_INSTALL; fi; }
            curl() { return 0; }
            sha256sum() { return 1; }
            install_caddy_from_verified_release
        ''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('UNSAFE_INSTALL', result.stdout)

    def test_unsupported_architecture_fails_before_download(self):
        result = self.run_shell('''
            dpkg() { echo unsupported; }
            curl() { echo UNEXPECTED_DOWNLOAD; }
            install_caddy_from_verified_release
        ''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('UNEXPECTED_DOWNLOAD', result.stdout)
