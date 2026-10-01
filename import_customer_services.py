#!/usr/bin/env python3
"""Import private customer-service records from a local JSON file."""

import argparse
from datetime import datetime
import json
from pathlib import Path
import secrets
import sqlite3

from input_limits import MAX_NAME_CHARS, MAX_NOTES_CHARS, validate_text


def _date(value, field):
    try:
        return datetime.strptime(str(value), "%Y-%m-%d").date().isoformat()
    except (TypeError, ValueError):
        raise ValueError(f"{field} must use YYYY-MM-DD")


def import_services(database, source):
    records = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(records, list) or not records:
        raise ValueError("source must contain a non-empty JSON array")
    if any(not isinstance(row, dict) for row in records):
        raise ValueError("each service record must be an object")

    db = sqlite3.connect(database, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    try:
        db.execute("BEGIN IMMEDIATE")
        accounts = {}
        for row in db.execute("SELECT id, name FROM accounts"):
            accounts.setdefault(row["name"], []).append(row["id"])
        requested = {str(row.get("account", "")) for row in records}
        missing = sorted(requested - accounts.keys())
        if missing:
            raise ValueError("unknown account names: " + ", ".join(missing))
        ambiguous = sorted(name for name in requested if len(accounts[name]) != 1)
        if ambiguous:
            raise ValueError("ambiguous account names: " + ", ".join(ambiguous))

        created = updated = 0
        for row in records:
            account_id = accounts[str(row["account"])][0]
            wechat_id = validate_text(row.get("wechat_id"), "wechat_id", MAX_NAME_CHARS, required=True)
            relationship = validate_text(row.get("relationship", "自用"), "relationship", 20, required=True)
            notes = validate_text(row.get("notes"), "notes", MAX_NOTES_CHARS)
            started_on = _date(row.get("started_on"), "started_on")
            expires_on = _date(row.get("expires_on"), "expires_on")
            if started_on > expires_on:
                raise ValueError("expires_on must not be earlier than started_on")

            existing = db.execute(
                '''SELECT id FROM customer_services
                   WHERE account_id=? AND wechat_id=? AND started_on=?''',
                (account_id, wechat_id, started_on),
            ).fetchone()
            if existing:
                db.execute(
                    '''UPDATE customer_services SET relationship=?, expires_on=?, notes=?,
                              updated_at=CURRENT_TIMESTAMP WHERE id=?''',
                    (relationship, expires_on, notes, existing["id"]),
                )
                updated += 1
            else:
                db.execute(
                    '''INSERT INTO customer_services (
                           account_id, wechat_id, relationship, started_on,
                           expires_on, status, sub_token, notes
                       ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?)''',
                    (
                        account_id, wechat_id, relationship, started_on,
                        expires_on, secrets.token_hex(16), notes,
                    ),
                )
                created += 1
        db.commit()
        return created, updated
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    created, updated = import_services(args.database, args.source)
    print(f"created={created} updated={updated}")


if __name__ == "__main__":
    main()
