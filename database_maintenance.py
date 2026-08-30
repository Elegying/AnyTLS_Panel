"""Small, persistent SQLite maintenance jobs and readiness metrics."""

import shutil
import time
from pathlib import Path

from input_limits import bounded_env_int


DEFAULT_TRAFFIC_LOG_RETENTION_DAYS = 90
MAINTENANCE_INTERVAL_SECONDS = 3600


def traffic_log_retention_days():
    return bounded_env_int(
        'ANYTLS_TRAFFIC_LOG_RETENTION_DAYS',
        DEFAULT_TRAFFIC_LOG_RETENTION_DAYS,
        1,
        3650,
    )


def prune_traffic_logs(db, *, force=False, now=None):
    """Prune old detail rows at most hourly while preserving account totals."""
    now = int(time.time() if now is None else now)
    row = db.execute(
        "SELECT value FROM maintenance_state WHERE key='traffic_log_prune'"
    ).fetchone()
    if not force and row is not None:
        try:
            last_run = int(row[0])
        except (TypeError, ValueError, OverflowError):
            last_run = 0
        if now - last_run < MAINTENANCE_INTERVAL_SECONDS:
            return 0

    retention = traffic_log_retention_days()
    cursor = db.execute(
        "DELETE FROM traffic_logs WHERE recorded_at < datetime('now', ?)",
        (f'-{retention} days',),
    )
    db.execute(
        "INSERT INTO maintenance_state (key, value, updated_at) "
        "VALUES ('traffic_log_prune', ?, CURRENT_TIMESTAMP) "
        "ON CONFLICT(key) DO UPDATE SET "
        "value=excluded.value, updated_at=CURRENT_TIMESTAMP",
        (str(now),),
    )
    db.commit()
    return max(0, cursor.rowcount)


def checkpoint_database(db):
    return tuple(db.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone())


def database_metrics(database_path):
    path = Path(database_path)
    wal_path = Path(f'{path}-wal')
    return {
        'database_bytes': path.stat().st_size if path.is_file() else 0,
        'wal_bytes': wal_path.stat().st_size if wal_path.is_file() else 0,
        'free_bytes': shutil.disk_usage(path.parent).free,
    }
