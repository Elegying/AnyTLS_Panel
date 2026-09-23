"""Small, ordered SQLite schema migrations for existing installations."""

SCHEMA_VERSION = 8


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


def _add_admin_session_version(db):
    columns = {row[1] for row in db.execute("PRAGMA table_info(admin_users)")}
    if "session_version" not in columns:
        db.execute(
            "ALTER TABLE admin_users ADD COLUMN "
            "session_version INTEGER NOT NULL DEFAULT 1"
        )


def _add_database_maintenance(db):
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_traffic_logs_recorded_at "
        "ON traffic_logs(recorded_at)"
    )
    db.execute(
        """CREATE TABLE IF NOT EXISTS maintenance_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) WITHOUT ROWID"""
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_rate_limits_window_start "
        "ON rate_limits(window_start)"
    )


def _add_customer_services(db):
    columns = {row[1] for row in db.execute("PRAGMA table_info(accounts)")}
    if "last_traffic_reset_on" not in columns:
        db.execute(
            "ALTER TABLE accounts ADD COLUMN last_traffic_reset_on TEXT DEFAULT ''"
        )
    db.execute(
        "UPDATE accounts SET last_traffic_reset_on=date('now', '+8 hours') "
        "WHERE COALESCE(last_traffic_reset_on, '')=''"
    )
    db.execute(
        """CREATE TABLE IF NOT EXISTS customer_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            wechat_id TEXT NOT NULL,
            relationship TEXT NOT NULL DEFAULT '自用',
            started_on TEXT NOT NULL,
            expires_on TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            sub_token TEXT NOT NULL UNIQUE,
            last_reminded_at TIMESTAMP,
            notes TEXT DEFAULT '',
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
            UNIQUE (account_id, wechat_id, started_on)
        )"""
    )
    db.execute(
        """CREATE TABLE IF NOT EXISTS service_renewals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_id INTEGER NOT NULL,
            old_expires_on TEXT NOT NULL,
            new_expires_on TEXT NOT NULL,
            notes TEXT DEFAULT '',
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (service_id) REFERENCES customer_services(id) ON DELETE CASCADE
        )"""
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_customer_services_account_id "
        "ON customer_services(account_id)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_customer_services_expires_on "
        "ON customer_services(expires_on, status)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_service_renewals_service_id "
        "ON service_renewals(service_id)"
    )


def _add_node_probe_results(db):
    columns = {row[1] for row in db.execute("PRAGMA table_info(nodes)")}
    for name, declaration in (("probe_result", "TEXT NOT NULL DEFAULT ''"),
                              ("probe_error", "TEXT NOT NULL DEFAULT ''"),
                              ("probe_attempt_at", "TEXT")):
        if name not in columns:
            db.execute(f"ALTER TABLE nodes ADD COLUMN {name} {declaration}")
    db.execute("""CREATE TABLE IF NOT EXISTS node_probe_leases (
        node_id INTEGER PRIMARY KEY, token TEXT NOT NULL, expires REAL NOT NULL
    )""")


def _add_node_filter(db):
    db.execute("""CREATE TABLE IF NOT EXISTS node_filter (
        id INTEGER PRIMARY KEY CHECK (id=1),
        enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
        keywords TEXT NOT NULL DEFAULT '[]'
    )""")
    db.execute('INSERT OR IGNORE INTO node_filter (id) VALUES (1)')


def _add_canonical_proxy(db):
    columns = {row[1] for row in db.execute('PRAGMA table_info(nodes)')}
    if 'clash_config' not in columns:
        db.execute("ALTER TABLE nodes ADD COLUMN clash_config TEXT NOT NULL DEFAULT ''")


_MIGRATIONS = (
    (1, _add_account_metadata_columns),
    (2, _add_rate_limits),
    (3, _add_admin_session_version),
    (4, _add_database_maintenance),
    (5, _add_customer_services),
    (6, _add_node_probe_results),
    (7, _add_node_filter),
    (8, _add_canonical_proxy),
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
