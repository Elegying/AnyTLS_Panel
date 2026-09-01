"""Bounded TCP/TLS node probes with explicit outbound-address policy."""

import ipaddress
import socket
import ssl
import time


def _validated_addresses(addresses, allow_private):
    validated = []
    for raw_address in addresses:
        try:
            address = str(raw_address).split('%', 1)[0]
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError('节点地址解析结果无效') from exc
        if not allow_private and not ip.is_global:
            raise ValueError('节点检测默认只允许公网地址')
        if address not in validated:
            validated.append(address)
    if not validated:
        raise ValueError('节点地址无法解析')
    return validated


def check_node_connect(host, port, timeout, resolver, *, allow_private=False):
    """Probe a resolved and pinned endpoint within one absolute deadline."""
    deadline = time.monotonic() + timeout
    try:
        addresses = _validated_addresses(
            resolver(host, port, deadline),
            allow_private,
        )
    except ValueError:
        return {
            'online': False,
            'status': 'offline',
            'msg': '节点地址无效或默认只允许公网地址',
            'latency': -1,
        }
    except (OSError, TimeoutError):
        return {
            'online': False,
            'status': 'offline',
            'msg': '节点地址解析失败',
            'latency': -1,
        }

    started = time.monotonic()
    last_error = None
    for address in addresses:
        sock = None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            sock = socket.create_connection((address, port), timeout=remaining)
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            tls_sock = context.wrap_socket(sock, server_hostname=host)
            tls_sock.close()
            latency = int((time.monotonic() - started) * 1000)
            return {
                'online': True,
                'status': 'online',
                'msg': 'TLS 连接成功',
                'latency': latency,
            }
        except ssl.SSLError:
            latency = int((time.monotonic() - started) * 1000)
            return {
                'online': True,
                'status': 'online',
                'msg': 'TCP 连接成功 (TLS 异常)',
                'latency': latency,
            }
        except (socket.timeout, TimeoutError):
            last_error = '连接超时'
        except ConnectionRefusedError:
            last_error = '连接被拒绝'
        except OSError:
            last_error = '连接失败'
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    return {
        'online': False,
        'status': 'offline',
        'msg': last_error or '连接失败',
        'latency': -1,
    }
