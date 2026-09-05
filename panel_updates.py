"""Read-only checks for the panel's published GitHub releases."""

import http.client
import json
from pathlib import Path
import re
import threading
import time


RELEASES_URL = 'https://github.com/Elegying/AnyTLS_Panel/releases'
_VERSION_PATTERN = re.compile(r'(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})')
_MAX_RESPONSE_BYTES = 256 * 1024


def parse_version(value):
    if not isinstance(value, str) or not _VERSION_PATTERN.fullmatch(value):
        raise ValueError('invalid release version')
    return tuple(int(part) for part in value.split('.'))


def read_current_version():
    try:
        with Path(__file__).with_name('VERSION').open(encoding='utf-8') as source:
            version = source.read(64).strip()
        parse_version(version)
        return version
    except (OSError, ValueError):
        return None


CURRENT_VERSION = read_current_version()


def _fetch_latest_release():
    # Fixed HTTPS destination, no redirects, cookies, credentials or customer data.
    connection = http.client.HTTPSConnection('api.github.com', timeout=5)
    try:
        connection.request('GET', '/repos/Elegying/AnyTLS_Panel/releases/latest', headers={
            'Accept': 'application/vnd.github+json',
            'User-Agent': 'AnyTLS-Panel-update-check',
            'X-GitHub-Api-Version': '2026-03-10',
        })
        response = connection.getresponse()
        if response.status in (403, 429):
            raise RuntimeError('GitHub 暂时限制了请求，请稍后再试。')
        if response.status != 200:
            raise RuntimeError('暂时无法获取正式版本，请稍后再试。')
        payload = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(payload) > _MAX_RESPONSE_BYTES:
            raise ValueError('release response too large')
        release = json.loads(payload)
        if (
            not isinstance(release, dict)
            or release.get('draft') is not False
            or release.get('prerelease') is not False
            or not isinstance(release.get('published_at'), str)
            or not release['published_at']
        ):
            raise ValueError('not a published stable release')
        tag = release.get('tag_name')
        if not isinstance(tag, str) or not tag.startswith('v'):
            raise ValueError('invalid release tag')
        parse_version(tag[1:])
        return tag[1:]
    finally:
        connection.close()


class ReleaseChecker:
    """Coalesce concurrent admin checks and cache public metadata in memory."""

    def __init__(self, current_version=CURRENT_VERSION):
        self.current_version = current_version
        self._lock = threading.Lock()
        self._result = None
        self._expires_at = 0

    def check(self):
        with self._lock:
            if self._result is not None and time.monotonic() < self._expires_at:
                return dict(self._result)
            result = {'current_version': self.current_version, 'status': 'error'}
            try:
                latest = _fetch_latest_release()
                result.update(latest_version=latest, release_url=f'{RELEASES_URL}/tag/v{latest}')
                if self.current_version is None:
                    result.update(status='unknown', message='当前版本无法识别，请核对安装文件。')
                elif parse_version(latest) > parse_version(self.current_version):
                    result.update(status='available', message=f'发现新版本 v{latest}')
                elif parse_version(latest) == parse_version(self.current_version):
                    result.update(status='current', message='已是最新正式版')
                else:
                    result.update(status='ahead', message=f'当前版本高于最新正式版 v{latest}')
            except RuntimeError as exc:
                result['message'] = str(exc)
            except (OSError, http.client.HTTPException):
                result['message'] = '无法连接 GitHub，请检查服务器网络后重试。'
            except (ValueError, RecursionError):
                result['message'] = '版本信息无效，请稍后再试。'
            self._expires_at = time.monotonic() + (60 if result['status'] == 'error' else 300)
            self._result = result
            return dict(result)
