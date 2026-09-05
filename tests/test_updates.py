"""Version checks and release selection must never imply an unverified update."""

from concurrent.futures import ThreadPoolExecutor
import http.client
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import panel_updates
import yaml
from test_app import authenticate_session, extract_csrf_token, load_app, REPO_ROOT
from test_reliability import run_shell


class ReleaseCheckTests(unittest.TestCase):
    def release_response(self, **overrides):
        payload = {
            'tag_name': 'v1.10.0', 'draft': False, 'prerelease': False,
            'published_at': '2026-09-05T00:00:00Z',
            'html_url': 'https://untrusted.example/release',
        }
        payload.update(overrides)
        response = mock.Mock(status=200)
        response.read.return_value = json.dumps(payload).encode()
        connection = mock.Mock()
        connection.getresponse.return_value = response
        return connection

    def test_version_file_is_validated_and_missing_file_does_not_break_panel(self):
        self.assertEqual(panel_updates.CURRENT_VERSION, (REPO_ROOT / 'VERSION').read_text().strip())
        for value in ('1.4.5\n', 'invalid', '01.2.3', '1.2.3-rc1'):
            with self.subTest(value=value), mock.patch.object(
                Path, 'open', return_value=io.StringIO(value)
            ):
                self.assertEqual(panel_updates.read_current_version(), '1.4.5' if value == '1.4.5\n' else None)
        with mock.patch.object(Path, 'open', side_effect=FileNotFoundError):
            self.assertIsNone(panel_updates.read_current_version())

    def test_numeric_comparison_unknown_and_ahead_never_offer_downgrades(self):
        for current, latest, expected in (
            ('1.9.9', '1.10.0', 'available'),
            ('1.10.0', '1.9.9', 'ahead'),
            ('2.0.0', '2.0.0', 'current'),
            (None, '1.10.0', 'unknown'),
        ):
            with self.subTest(current=current, latest=latest), mock.patch.object(
                panel_updates, '_fetch_latest_release', return_value=latest
            ):
                result = panel_updates.ReleaseChecker(current).check()
                self.assertEqual(result['status'], expected)
                self.assertEqual(result['release_url'], f'{panel_updates.RELEASES_URL}/tag/v{latest}')

    def test_only_fixed_public_github_endpoint_is_contacted(self):
        connection = self.release_response()
        with mock.patch.object(panel_updates.http.client, 'HTTPSConnection', return_value=connection) as factory:
            result = panel_updates.ReleaseChecker('1.9.9').check()
        factory.assert_called_once_with('api.github.com', timeout=5)
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ('GET', '/repos/Elegying/AnyTLS_Panel/releases/latest'))
        self.assertNotIn('Authorization', kwargs['headers'])
        self.assertNotIn('Cookie', kwargs['headers'])
        self.assertEqual(result['release_url'], f'{panel_updates.RELEASES_URL}/tag/v1.10.0')
        connection.close.assert_called_once()

    def test_invalid_release_metadata_never_becomes_an_update(self):
        for overrides in (
            {'draft': True}, {'prerelease': True}, {'draft': 'false'},
            {'published_at': None}, {'tag_name': 'v1.5.0-rc1'},
            {'tag_name': 'v1.2.3/path'}, {'tag_name': 123},
            {'tag_name': '1.2.3'}, {'tag_name': 'v01.2.3'},
        ):
            with self.subTest(overrides=overrides), mock.patch.object(
                panel_updates.http.client, 'HTTPSConnection', return_value=self.release_response(**overrides)
            ):
                result = panel_updates.ReleaseChecker('1.4.0').check()
                self.assertEqual(result['status'], 'error')
                self.assertNotIn('release_url', result)

    def test_http_failures_redirects_and_malformed_bodies_fail_closed(self):
        for status, payload in (
            (403, b'private upstream text'), (429, b''), (404, b''), (302, b''),
            (200, b'[]'), (200, b'{invalid'), (200, b'\xff'),
            (200, b'x' * (panel_updates._MAX_RESPONSE_BYTES + 1)),
        ):
            connection = self.release_response()
            connection.getresponse.return_value.status = status
            connection.getresponse.return_value.read.return_value = payload
            with self.subTest(status=status, size=len(payload)), mock.patch.object(
                panel_updates.http.client, 'HTTPSConnection', return_value=connection
            ):
                result = panel_updates.ReleaseChecker('1.4.0').check()
                self.assertEqual(result['status'], 'error')
                self.assertNotIn('private upstream', result['message'])
                connection.close.assert_called_once()

    def test_network_errors_are_safe_and_expire_so_retry_can_recover(self):
        for failure in (TimeoutError('secret detail'), http.client.HTTPException('secret detail')):
            checker = panel_updates.ReleaseChecker('1.4.0')
            with mock.patch.object(panel_updates, '_fetch_latest_release', side_effect=failure) as fetch, \
                    mock.patch.object(panel_updates.time, 'monotonic', return_value=100):
                first = checker.check()
                self.assertEqual(first['status'], 'error')
                self.assertNotIn('secret detail', first['message'])
                self.assertEqual(checker.check(), first)
                fetch.assert_called_once()
            with mock.patch.object(panel_updates.time, 'monotonic', return_value=161), \
                    mock.patch.object(panel_updates, '_fetch_latest_release', return_value='1.5.0'):
                self.assertEqual(checker.check()['status'], 'available')

    def test_concurrent_checks_share_one_request_and_success_cache_expires(self):
        checker = panel_updates.ReleaseChecker('1.4.0')

        def fetch_release():
            time.sleep(0.03)
            return '1.5.0'

        with mock.patch.object(panel_updates, '_fetch_latest_release', side_effect=fetch_release) as fetch, \
                mock.patch.object(panel_updates.time, 'monotonic', return_value=100):
            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(lambda _: checker.check(), range(6)))
            self.assertTrue(all(result['status'] == 'available' for result in results))
            fetch.assert_called_once()
            results[0]['status'] = 'tampered'
            self.assertEqual(checker.check()['status'], 'available')
        with mock.patch.object(panel_updates.time, 'monotonic', return_value=401), \
                mock.patch.object(panel_updates, '_fetch_latest_release', return_value='1.6.0') as fetch:
            self.assertEqual(checker.check()['latest_version'], '1.6.0')
            fetch.assert_called_once()

    def test_ui_and_endpoint_require_admin_csrf_and_explicit_click(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = load_app(Path(tmp) / 'test.db')
            client = module.app.test_client()
            result = {'status': 'current', 'message': '已是最新正式版'}
            with mock.patch.object(module._release_checker, 'check', return_value=result) as check:
                csrf = extract_csrf_token(client.get('/login').get_data(as_text=True))
                self.assertEqual(client.post('/api/updates/check', headers={'X-CSRFToken': csrf}).status_code, 302)
                authenticate_session(module, client)
                page = client.get('/').get_data(as_text=True)
                self.assertIn(f'v{panel_updates.CURRENT_VERSION}', page)
                self.assertIn('检查更新', page)
                self.assertEqual(client.get('/api/updates/check').status_code, 405)
                self.assertEqual(client.post('/api/updates/check').status_code, 400)
                check.assert_not_called()
                response = client.post('/api/updates/check', headers={
                    'X-CSRFToken': extract_csrf_token(page),
                })
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json(), result)
                check.assert_called_once()
                check.return_value = {'status': 'error', 'message': '无法连接 GitHub'}
                response = client.post('/api/updates/check', headers={'X-CSRFToken': extract_csrf_token(page)})
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.get_json()['status'], 'error')


class DeploymentSourceTests(unittest.TestCase):
    def test_download_failure_never_executes_partial_installer_and_cleans_tempfile(self):
        command = next(line for line in (REPO_ROOT / 'README.md').read_text().splitlines()
                       if line.startswith('(set -e; installer_dir='))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            curl = root / 'curl'
            curl.write_text('''#!/bin/bash
while (( $# )); do
    if [[ "$1" == '-o' ]]; then output="$2"; shift; fi
    shift
done
printf 'touch "$TEST_EXECUTED_MARKER"\\n' > "$output"
printf '%s' "$output" > "$TEST_CREATED_DOWNLOAD"
exit "$TEST_CURL_STATUS"
''')
            curl.chmod(0o700)
            for exit_status in (22, 28, 0):
                with self.subTest(exit_status=exit_status):
                    marker = root / 'executed'
                    record = root / 'download-path'
                    result = subprocess.run(['bash', '-c', command], capture_output=True, env={
                        **os.environ, 'PATH': f'{root}:/usr/bin:/bin',
                        'TEST_CURL_STATUS': str(exit_status),
                        'TEST_EXECUTED_MARKER': str(marker), 'TEST_CREATED_DOWNLOAD': str(record),
                    })
                    self.assertEqual(result.returncode, exit_status, result.stderr)
                    self.assertEqual(marker.exists(), exit_status == 0)
                    self.assertFalse(Path(record.read_text()).exists())

    def test_release_workflow_rejects_a_tag_different_from_installed_version(self):
        workflow = yaml.safe_load((REPO_ROOT / '.github/workflows/release.yml').read_text())
        step = next(step for step in workflow['jobs']['release']['steps']
                    if step['name'] == 'Validate release tag')
        validation = step['run'].split('git fetch origin main')[0]
        for tag, valid in ((f'v{panel_updates.CURRENT_VERSION}', True), ('v999.0.0', False), ('main', False)):
            with self.subTest(tag=tag):
                result = subprocess.run(['bash', '-ec', validation], cwd=REPO_ROOT,
                                        env={**os.environ, 'RELEASE_TAG': tag}, capture_output=True)
                self.assertEqual(result.returncode == 0, valid, result.stderr)

    def test_explicit_ref_uses_git_tag_despite_adjacent_old_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'repo'
            source.mkdir()
            required = (
                'app.py', 'database_maintenance.py', 'db_migrations.py', 'input_limits.py',
                'node_probe.py', 'protocol_codecs.py', 'security_utils.py', 'sqlite_rate_limit.py',
                'traffic_token.py', 'requirements.txt', 'templates/base.html', 'VERSION',
            )
            for name in required:
                path = source / name
                path.parent.mkdir(exist_ok=True)
                path.write_text('2.0.0\n' if name == 'VERSION' else 'new source\n')
            (source / 'release-files.txt').write_text('\n'.join(required) + '\n')
            git_env = {**os.environ, 'GIT_AUTHOR_NAME': 'Fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                       'GIT_COMMITTER_NAME': 'Fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}

            def git(*args):
                subprocess.run(['git', '-C', str(source), *args], env=git_env, check=True, capture_output=True)

            git('init', '-q')
            git('add', '.')
            git('commit', '-qm', 'fixture')
            git('tag', 'v2.0.0')
            git('tag', 'v2.0.1')  # Deliberately mismatched VERSION.
            git('branch', 'v2.0.2')  # A release-looking branch is not a tag.
            body = r'''
PANEL_DIR="$TEST_ROOT/installed"
validate_panel_dir() { :; }
validate_install_target() { :; }
prepare_release_source
[[ "$(cat "$RELEASE_SOURCE/app.py")" == 'new source' ]]
[[ "$(cat "$RELEASE_SOURCE/VERSION")" == '2.0.0' ]]
'''
            for ref, message in (
                ('v2.0.0', None), ('v2.0.1', 'VERSION does not match'),
                ('v2.0.2', 'not a tag'),
            ):
                with self.subTest(ref=ref):
                    result = run_shell('deploy.sh', body, TEST_ROOT=root,
                                       ANYTLS_REPO_URL=source, ANYTLS_REPO_REF=ref)
                    if message is None:
                        self.assertEqual(result.returncode, 0, result.stderr)
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(message, result.stderr)
                    self.assertFalse((root / 'installed').exists())


if __name__ == '__main__':
    unittest.main()
