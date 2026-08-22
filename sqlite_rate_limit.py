"""Persistent fixed-window request limiting backed by the application SQLite DB."""

import sqlite3
import time
from functools import wraps

from flask import jsonify, request


def _consume(db, bucket, subject, limit, period_seconds):
    now = int(time.time())
    window_start = now - (now % period_seconds)
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute(
            "DELETE FROM rate_limits WHERE window_start < ?",
            (now - 86400,),
        )
        row = db.execute(
            "SELECT window_start, request_count FROM rate_limits "
            "WHERE bucket=? AND subject=?",
            (bucket, subject),
        ).fetchone()
        if row is None or row[0] != window_start:
            db.execute(
                "INSERT INTO rate_limits "
                "(bucket, subject, window_start, request_count) VALUES (?, ?, ?, 1) "
                "ON CONFLICT(bucket, subject) DO UPDATE SET "
                "window_start=excluded.window_start, request_count=1",
                (bucket, subject, window_start),
            )
            allowed = True
        elif row[1] < limit:
            db.execute(
                "UPDATE rate_limits SET request_count=request_count + 1 "
                "WHERE bucket=? AND subject=?",
                (bucket, subject),
            )
            allowed = True
        else:
            allowed = False
        db.commit()
    except Exception:
        db.rollback()
        raise
    return allowed, max(1, window_start + period_seconds - now)


def enforce_rate_limit(get_db, bucket, limit, period_seconds, error_message):
    subject = request.remote_addr or "unknown"
    try:
        allowed, retry_after = _consume(
            get_db(), bucket, subject, limit, period_seconds
        )
    except sqlite3.Error:
        return jsonify({"error": "rate limiter unavailable"}), 503
    if allowed:
        return None
    headers = {"Retry-After": str(retry_after)}
    if request.path.startswith("/api/"):
        return jsonify({"error": error_message}), 429, headers
    return error_message, 429, headers


def rate_limit(get_db, bucket, limit, period_seconds, *, methods=None,
               error_message="请求过于频繁，请稍后再试"):
    limited_methods = {method.upper() for method in methods} if methods else None

    def decorator(view):
        @wraps(view)
        def decorated(*args, **kwargs):
            if limited_methods is None or request.method in limited_methods:
                rejected = enforce_rate_limit(
                    get_db,
                    bucket,
                    limit,
                    period_seconds,
                    error_message,
                )
                if rejected is not None:
                    return rejected
            return view(*args, **kwargs)

        decorated._sqlite_rate_limit = True
        return decorated

    return decorator
