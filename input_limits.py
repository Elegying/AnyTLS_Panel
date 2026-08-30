"""Shared input and resource limits for the web and protocol layers."""

import os


DEFAULT_MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_SUBSCRIPTION_TEXT_CHARS = 2 * 1024 * 1024
MAX_NAME_CHARS = 200
MAX_NOTES_CHARS = 4000
MAX_RENAME_TEXT_CHARS = 200
MAX_HOST_CHARS = 253
MAX_TRAFFIC_BATCH_ITEMS = 100
SQLITE_INTEGER_MAX = 2**63 - 1


def bounded_env_int(name, default, minimum, maximum):
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError, OverflowError):
        raise RuntimeError(f'{name} must be an integer') from None
    if not minimum <= value <= maximum:
        raise RuntimeError(f'{name} must be between {minimum} and {maximum}')
    return value


def validate_text(value, field_name, max_chars, *, required=False):
    text = str(value or '').strip()
    if required and not text:
        raise ValueError(f'{field_name}不能为空')
    if len(text) > max_chars:
        raise ValueError(f'{field_name}不能超过{max_chars}个字符')
    return text
