"""
SSRF-safe HTTP session.

Name-based checks are not enough on their own: a hostname can resolve to an internal address,
or re-resolve differently between the check and the connection (DNS rebinding). This session
verifies the peer address of every socket *after* it connects and refuses any destination that
is not globally routable. Environment proxies are ignored so the check applies to the real peer.
"""

import ipaddress

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import NewConnectionError


class BlockedDestinationError(NewConnectionError):
    pass


def is_allowed_peer(addr: ipaddress._BaseAddress) -> bool:
    """Only globally routable destinations may be contacted."""
    return addr.is_global


class _PeerCheckMixin:
    def _new_conn(self):  # type: ignore[override]
        sock = super()._new_conn()
        peer = sock.getpeername()[0].split("%")[0]
        addr = ipaddress.ip_address(peer)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if not is_allowed_peer(addr):
            sock.close()
            raise BlockedDestinationError(self, f"Blocked connection to non-public address {addr}")
        return sock


class _GuardedHTTPConnection(_PeerCheckMixin, HTTPConnection):
    pass


class _GuardedHTTPSConnection(_PeerCheckMixin, HTTPSConnection):
    pass


class _GuardedHTTPPool(HTTPConnectionPool):
    ConnectionCls = _GuardedHTTPConnection


class _GuardedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _GuardedHTTPSConnection


class _GuardedAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {"http": _GuardedHTTPPool, "https": _GuardedHTTPSPool}


def guarded_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    adapter = _GuardedAdapter(max_retries=0)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session
