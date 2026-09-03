#!/usr/bin/env python3
"""Import private customer-service records from a local JSON file."""

import argparse
from datetime import datetime
import json
from pathlib import Path
import secrets
import sqlite3


def _date(value, field):
    try:
        return datetime.strptime(str(value), "%Y-%m-%d").date().isoformat()
    except (TypeError, ValueError):
        raise ValueError(f"{field} must use YYYY-MM-DD")


def import_services(database, source):
    records = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(records, list) or not records:
        raise ValueError("source must contain a non-empty JSON array")

    db = sqlite3.connect(database, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    try:
        accounts = {
            row["name"]: row["id"]
            for row in db.execute("SELECT id, name FROM accounts")
        }
        missing = sorted({str(row.get("account", "")) for row in records} - accounts.keys())
        if missing:
            raise ValueError("unknown account names: " + ", ".join(missing))

        created = updated = 0
        db.execute("BEGIN IMMEDIATE")
        for row in records:
            account_id = accounts[str(row["account"])]
            wechat_id = str(row.get("wechat_id", "")).strip()
            relationship = str(row.get("relationship", "自用")).strip()
            notes = str(row.get("notes", "")).strip()
            started_on = _date(row.get("started_on"), "started_on")
            expires_on = _date(row.get("expires_on"), "expires_on")
            if not wechat_id or len(wechat_id) > 120:
                raise ValueError("wechat_id must contain 1-120 characters")
            if not relationship or len(relationship) > 20:
                raise ValueError("relationship must contain 1-20 characters")
            if len(notes) > 2000:
                raise ValueError("notes may contain at most 2000 characters")
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
