#!/usr/bin/env python3
"""Generate account-scoped traffic collector tokens without starting the panel."""

import argparse
import base64
import hashlib
import hmac
import os
from pathlib import Path


def make_account_traffic_token(master_token, account_id):
    if isinstance(account_id, bool):
        raise ValueError('account_id must be a positive integer')
    try:
        account_id = int(account_id)
    except (TypeError, ValueError, OverflowError):
        raise ValueError('account_id must be a positive integer') from None
    if account_id < 1:
        raise ValueError('account_id must be a positive integer')
    master_token = str(master_token).strip()
    if not master_token:
        raise ValueError('traffic api token is empty')

    message = f'account:{account_id}'.encode()
    signature = base64.urlsafe_b64encode(
        hmac.new(master_token.encode(), message, hashlib.sha256).digest()
    ).decode().rstrip('=')
    return f'atp1.{account_id}.{signature}'


def main(argv=None):
    default_token_file = (
        Path(__file__).resolve().parent / 'data' / '.traffic_api_token'
    )
    parser = argparse.ArgumentParser(
        description='Generate a traffic collector token scoped to one account.',
    )
    parser.add_argument('account_id', type=int, help='positive panel account ID')
    parser.add_argument(
        '--token-file',
        default=os.environ.get(
            'ANYTLS_TRAFFIC_API_TOKEN_FILE',
            str(default_token_file),
        ),
        help='master traffic token file (defaults to the deployed data path)',
    )
    args = parser.parse_args(argv)

    token_file = Path(args.token_file)
    if token_file.is_symlink() or not token_file.is_file():
        parser.error(f'token file must be a regular non-symlink file: {token_file}')
    try:
        scoped_token = make_account_traffic_token(
            token_file.read_text(encoding='utf-8'),
            args.account_id,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(scoped_token)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
