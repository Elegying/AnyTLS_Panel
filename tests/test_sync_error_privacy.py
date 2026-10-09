"""Exercise response privacy and rollback at the real sync endpoints."""

from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from test_app import authenticate_session, load_app


class SyncErrorPrivacyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Path(temporary.name) / 'panel.db'
        self.module = load_app(self.database)
        self.module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        with closing(sqlite3.connect(self.database)) as db, db:
            for name in ('first', 'second'):
                account_id = db.execute(
                    'INSERT INTO accounts (name, subscribe_url, traffic_used_bytes, node_count) '
                    'VALUES (?, ?, 10, 1)', (name, f'https://example.com/{name}'),
                ).lastrowid
                db.execute('INSERT INTO nodes (account_id, name, host, port, password) '
                           "VALUES (?, 'original', 'example.com', 443, 'old')", (account_id,))
        self.node = {'name': 'updated', 'host': 'example.com', 'port': 443,
                     'password': 'new', 'protocol': 'anytls',
                     'raw_uri': 'anytls://new@example.com:443#updated'}

    def assert_original_preserved(self):
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('SELECT name, password FROM nodes WHERE account_id=1')
                             .fetchall(), [('original', 'old')])
            self.assertEqual(db.execute('SELECT traffic_used_bytes FROM accounts WHERE id=1')
                             .fetchone()[0], 10)

    def exercise_failure(self, endpoint, phase):
        secret = 'PRIVATE_INTERNAL_DETAIL https://example.com/?token=secret'
        real_store = self.module._store_synced_account

        def fetch(url):
            if phase == 'fetch' and url.endswith('/first'):
                raise ValueError(secret)
            return [self.node], {'used_bytes': 123}

        def store(db, account, nodes, traffic):
            real_store(db, account, nodes, traffic)
            if phase == 'store' and account['id'] == 1:
                raise ValueError(secret)

        with mock.patch.object(self.module, 'parse_subscribe_url', side_effect=fetch), \
                mock.patch.object(self.module, '_store_synced_account', side_effect=store):
            with self.module.app.test_client() as client:
                authenticate_session(self.module, client)
                response = client.post(endpoint, follow_redirects=True)
                self.assertEqual(response.status_code, 200)
                self.assertNotIn('PRIVATE_INTERNAL_DETAIL', response.get_data(as_text=True))
                self.assertNotIn('token=secret', response.get_data(as_text=True))
                if endpoint == '/api/sync-all':
                    self.assertEqual([r['status'] for r in response.get_json()['results']],
                                     ['error', 'ok'])
        self.assert_original_preserved()
        if endpoint == '/api/sync-all':
            with closing(sqlite3.connect(self.database)) as db:
                self.assertEqual(db.execute('SELECT name FROM nodes WHERE account_id=2')
                                 .fetchone()[0], 'updated')

    def test_bulk_fetch_failure_is_private_and_other_accounts_continue(self):
        self.exercise_failure('/api/sync-all', 'fetch')

    def test_bulk_store_failure_is_private_and_rolled_back(self):
        self.exercise_failure('/api/sync-all', 'store')

    def test_single_fetch_failure_is_private(self):
        self.exercise_failure('/accounts/1/sync', 'fetch')

    def test_single_store_failure_is_private_and_rolled_back(self):
        self.exercise_failure('/accounts/1/sync', 'store')
