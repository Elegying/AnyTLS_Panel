#!/usr/bin/env python3
"""Fair, bounded scheduled node verification; no subscription refreshes."""
import json
import time


def check_due_nodes(panel, limit=32, budget=45):
    deadline = time.monotonic() + budget
    results = []
    with panel.app.app_context(), panel._bulk_operation_lock() as acquired:
        if not acquired:
            return {'checked': 0, 'busy': True}
        db = panel.get_db()
        nodes = [dict(n) for n in db.execute('''SELECT n.* FROM nodes n JOIN accounts a ON a.id=n.account_id
            WHERE a.status='active'
            ORDER BY COALESCE(n.probe_attempt_at, ''), n.id LIMIT ?''', (limit,))]
        for start in range(0, len(nodes), 2):
            if deadline - time.monotonic() < 1:
                break
            wave = [(n, panel._acquire_probe(n['id'])) for n in nodes[start:start + 2]]
            wave = [(n, token) for n, token in wave if token]

            def check(item):
                node, token = item
                try:
                    result = panel._run_probe(node, timeout=max(0.1, min(8, deadline - time.monotonic())))
                except Exception:
                    result = None
                return node, token, result

            for node, token, result in panel._bounded_parallel_map(check, wave, max_workers=2):
                health = panel._save_probe(node, token, result)
                if health:
                    results.append(health['status'])
    return {'checked': len(results), 'verified': results.count('verified'),
            'failed': results.count('failed'), 'incomplete': results.count('error')}


if __name__ == '__main__':
    import app as panel
    print(json.dumps(check_due_nodes(panel)))
