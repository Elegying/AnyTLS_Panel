"""密码哈希工具：PBKDF2（带盐）+ 兼容旧版无盐 SHA256。

旧库里 password_hash 是 64 位十六进制的无盐 SHA256，安全性差。
本模块统一用 werkzeug 的 PBKDF2-SHA256，并在登录校验时识别旧格式，
校验通过后由调用方自动升级为新格式。
"""

import hashlib
import hmac
import re

from werkzeug.security import check_password_hash, generate_password_hash

# 旧格式：纯 64 位十六进制（无盐 SHA256）
_LEGACY_SHA256_RE = re.compile(r'^[0-9a-f]{64}$')


def hash_password(password: str) -> str:
    """生成新的 PBKDF2-SHA256 哈希（含随机盐）。"""
    return generate_password_hash(password or '', method='pbkdf2:sha256')


def _is_legacy(stored_hash: str) -> bool:
    return bool(_LEGACY_SHA256_RE.match(stored_hash or ''))


def verify_password(stored_hash: str, candidate: str):
    """校验密码。

    返回 (是否匹配, 是否需要升级哈希)。
    需要升级 = 旧格式且校验通过，调用方应据此重新写入 hash_password(candidate)。
    """
    stored_hash = stored_hash or ''
    candidate = candidate or ''
    if _is_legacy(stored_hash):
        legacy = hashlib.sha256(candidate.encode()).hexdigest()
        ok = hmac.compare_digest(legacy, stored_hash)
        return ok, ok  # 旧格式校验通过即需要升级
    try:
        return check_password_hash(stored_hash, candidate), False
    except (ValueError, TypeError):
        return False, False
