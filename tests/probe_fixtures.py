"""Synthetic probe evidence only; no real endpoints or credentials."""
from datetime import datetime, timezone


def entry_result(latency=12):
    return {'version': 1, 'online': True, 'status': 'entry', 'msg': '入口可达，代理未验证',
            'latency': latency, 'checked_at': datetime.now(timezone.utc).isoformat(),
            'tls_mode': 'strict', 'source': 'panel_server',
            'stages': {key: {'state': 'success' if key in ('dns', 'tcp', 'tls') else 'not_run',
                             'detail': '模拟入口证据' if key in ('dns', 'tcp', 'tls') else '未验证'}
                       for key in ('dns', 'tcp', 'tls', 'auth', 'access')}}
