"""Small, ordered SQLite schema migrations for existing installations."""

SCHEMA_VERSION = 2


def _add_account_metadata_columns(db):
    columns = {row[1] for row in db.execute("PRAGMA table_info(accounts)")}
    for column, declaration in (
        ("sub_token", "TEXT DEFAULT ''"),
        ("traffic_upload_bytes", "INTEGER DEFAULT 0"),
        ("traffic_download_bytes", "INTEGER DEFAULT 0"),
        ("expire_date", "TEXT DEFAULT ''"),
    ):
        if column not in columns:
            db.execute(f"ALTER TABLE accounts ADD COLUMN {column} {declaration}")


def _add_rate_limits(db):
    db.execute(
        """CREATE TABLE IF NOT EXISTS rate_limits (
            bucket TEXT NOT NULL,
            subject TEXT NOT NULL,
            window_start INTEGER NOT NULL,
            request_count INTEGER NOT NULL,
            PRIMARY KEY (bucket, subject)
        ) WITHOUT ROWID"""
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_rate_limits_window_start "
        "ON rate_limits(window_start)"
    )


_MIGRATIONS = (
    (1, _add_account_metadata_columns),
    (2, _add_rate_limits),
)


def apply_schema_migrations(db):
    """Apply each migration once while serializing concurrent initializers."""
    db.execute(
        """CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    db.commit()
    db.execute("BEGIN IMMEDIATE")
    try:
        applied = {
            row[0] for row in db.execute("SELECT version FROM schema_migrations")
        }
        for version, migration in _MIGRATIONS:
            if version in applied:
                continue
            migration(db)
            db.execute(
                "INSERT INTO schema_migrations (version) VALUES (?)",
                (version,),
            )
        db.commit()
    except Exception:
        db.rollback()
        raise
