"""
Shared TLS contexts for outbound HTTPS fetches.

requests builds a fresh SSLContext for every Session, and on every send it
hands urllib3 a ca_certs path, so the CA bundle is parsed again for each new
connection. The audit opens a new Session per fetch (crt.sh, Cert Spotter,
the MTA-STS policy, the BIMI logo), and loading the bundle costs about 64 ms
of CPU per fetch on the production droplet. Each process builds the contexts
here once and reuses them.

Two contexts, because urllib3 mutates a context it is given. When a pool
carries assert_hostname (the pinned-host path in checks_extra), urllib3 sets
check_hostname to False on the context and matches the certificate against
assert_hostname itself. Sharing that context with an ordinary fetch would
leave the ordinary fetch without hostname verification, so the pinned path
gets its own.
"""

import ssl
import threading

import requests
from requests.adapters import HTTPAdapter

_lock = threading.Lock()
_contexts = {}


def shared_context(name: str = "default") -> ssl.SSLContext:
    """One verifying SSLContext per name per process, built on first use."""
    ctx = _contexts.get(name)
    if ctx is None:
        with _lock:
            ctx = _contexts.get(name)
            if ctx is None:
                ctx = ssl.create_default_context(cafile=requests.certs.where())
                _contexts[name] = ctx
    return ctx


class SharedContextAdapter(HTTPAdapter):
    """HTTPAdapter whose pools all use one process-wide SSLContext.

    cert_verify is overridden for the verify=True case so that requests does
    not set ca_certs on the connection. With ca_certs set, urllib3 calls
    load_verify_locations on the context for every new connection, which is
    exactly the cost this module exists to remove. The context already holds
    the same bundle.
    """

    context_name = "default"

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = shared_context(self.context_name)
        super().init_poolmanager(*args, **kwargs)

    def cert_verify(self, conn, url, verify, cert):
        if not url.lower().startswith("https"):
            super().cert_verify(conn, url, verify, cert)
            return
        # urllib3 applies verify=False or a CA bundle path to the context it
        # is given, and that context is shared: one such fetch would change
        # verification for every later fetch in the process. Refuse instead.
        if verify is not True or cert:
            raise ValueError("http_tls shares one SSLContext and verifies with the "
                             "default bundle only; use requests directly for "
                             "verify=False, a custom CA bundle or a client cert")
        conn.cert_reqs = "CERT_REQUIRED"
        conn.ca_certs = None
        conn.ca_cert_dir = None


def session(adapter: HTTPAdapter = None) -> requests.Session:
    """A fresh Session (callers close it) with the shared context mounted.

    A Session per call is kept on purpose: urllib3 snapshots the pool
    arguments at pool creation, and the pinned-host adapter changes them per
    request. Only the SSLContext underneath is shared.
    """
    s = requests.Session()
    s.mount("https://", adapter if adapter is not None else SharedContextAdapter())
    return s


def get(url, **kwargs) -> requests.Response:
    """requests.get with the shared context. The CT check calls this, and the
    tests patch http_tls.get where they used to patch requests.get."""
    with session() as s:
        return s.get(url, **kwargs)
