"""Regression checks for inactive-account edits and exact backup source paths."""
from contextlib import closing
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from test_app import authenticate_session, load_app


class ReviewRoundFour(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_service_on_inactive_account_can_be_edited_without_reassignment(self):
        panel = load_app(self.root / 'panel.db')
        panel.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        client = panel.app.test_client()
        authenticate_session(panel, client)
        with panel.app.app_context():
            db = panel.get_db()
            db.executemany('INSERT INTO accounts(name, subscribe_url, status) VALUES (?, ?, ?)',
                           [('original', 'fixture', 'disabled'), ('other', 'fixture', 'suspended')])
            db.execute("""INSERT INTO customer_services
                       (account_id, wechat_id, started_on, expires_on, sub_token)
                       VALUES (1, 'fixture', '2026-01-01', '2027-01-01', 'fixture-token')""")
            db.commit()
        values = dict(account_id=1, wechat_id='fixture', relationship='自用',
                      started_on='2026-01-01', expires_on='2027-01-01', notes='updated')
        for status in ('disabled', 'suspended'):
            with self.subTest(status=status):
                with panel.app.app_context():
                    db = panel.get_db()
                    db.execute('UPDATE accounts SET status=? WHERE id=1', (status,))
                    db.commit()
                response = client.post('/services/1/edit', data=values, headers={'X-Panel-Form': '1'})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json, {'redirect': '/services/1'})
                with panel.app.app_context():
                    db = panel.get_db()
                    row = db.execute('SELECT * FROM customer_services').fetchone()
                    self.assertEqual((row['account_id'], row['notes'], row['sub_token']), (1, 'updated', 'fixture-token'))
                    self.assertEqual(db.execute('SELECT status FROM accounts WHERE id=1').fetchone()[0], status)
                self.assertEqual(client.get('/sub/fixture-token').status_code, 404)
        for endpoint in ('/services/1/edit', '/services/add'):
            response = client.post(endpoint, data={**values, 'account_id': 2}, headers={'X-Panel-Form': '1'})
            self.assertEqual(response.status_code, 422)
        with panel.app.app_context():
            self.assertEqual(panel.get_db().execute('SELECT account_id FROM customer_services').fetchone()[0], 1)

    def test_backup_reads_exact_database_path_instead_of_uri_interpretation(self):
        script = Path(__file__).resolve().parent.parent / 'backup.sh'
        # Execute the actual backup Python body without root or system mutations.
        python_body = re.findall(r"<<'PY'\n(.*?)\nPY", script.read_text(), re.S)[1]
        decoy = self.root / 'panel.db'
        with closing(sqlite3.connect(decoy)) as db, db:
            db.execute('CREATE TABLE proof(value TEXT)')
            db.execute("INSERT INTO proof VALUES ('wrong-source')")
        for suffix in ('#snapshot', '?snapshot', '%23snapshot', ' space', '中文'):
            with self.subTest(suffix=suffix):
                source = self.root / ('panel.db' + suffix)
                target = self.root / 'backup.db'
                with closing(sqlite3.connect(source)) as db, db:
                    db.execute('CREATE TABLE proof(value TEXT)')
                    db.execute('INSERT INTO proof VALUES (?)', (suffix,))
                result = subprocess.run([sys.executable, '-', str(source), str(target)],
                                        input=python_body, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                with closing(sqlite3.connect(target)) as db:
                    self.assertEqual(db.execute('SELECT value FROM proof').fetchone()[0], suffix)
                target.unlink()
        missing = self.root / 'missing.db?mode=rw'
        result = subprocess.run([sys.executable, '-', str(missing), str(self.root / 'missing-backup.db')],
                                input=python_body, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(missing.exists())

    def test_backup_includes_committed_wal_data_from_live_database(self):
        script = Path(__file__).resolve().parent.parent / 'backup.sh'
        python_body = re.findall(r"<<'PY'\n(.*?)\nPY", script.read_text(), re.S)[1]
        source, target = self.root / 'live#panel.db', self.root / 'wal-backup.db'
        with closing(sqlite3.connect(source)) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE proof(value TEXT)')
            db.execute("INSERT INTO proof VALUES ('committed-in-wal')")
            db.commit()
            self.assertTrue(Path(str(source) + '-wal').exists())
            result = subprocess.run([sys.executable, '-', str(source), str(target)],
                                    input=python_body, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            with closing(sqlite3.connect(target)) as backup:
                self.assertEqual(backup.execute('SELECT value FROM proof').fetchone()[0], 'committed-in-wal')
