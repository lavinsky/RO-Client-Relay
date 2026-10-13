"""Credential safety: what may be logged, and what may be fed to the consumer.

Every check that decides "is this HTTP" or "is this the login socket" lives here, so the
answer is the same everywhere."""
import re

LOGIN_SOCK = re.compile(r':(6900|3000)$')       # login server + HTTP config/token API: may carry credentials
NON_GAME_SOCK = re.compile(r':(3000|6700)$')    # HTTP config API + Relay backend: not RO packet streams
HTTP_PREFIXES = (b'POST', b'GET ', b'HTTP', b'PUT ', b'HEAD', b'--')   # '--' = multipart body


def is_login_sock(sock):
    return LOGIN_SOCK.search(sock) is not None


def is_game_sock(sock):
    return NON_GAME_SOCK.search(sock) is None


def looks_like_http(data):
    """uaRO runs HTTP/token exchanges next to the RO stream; those bytes are not RO packets."""
    return bytes(data[:4]).startswith(HTTP_PREFIXES)


def redact_login(P):
    """Credential-safe copy of a client->server login-socket packet: 0x0064 keeps only
    id/version/clienttype (user/pass zeroed) so the consumer can still witness it; any other
    login-socket send (token logins, HTTP) returns None = never fed."""
    if len(P) == 55 and P[:2] == b'\x64\x00':
        return P[:6] + bytes(48) + P[54:]
    return None


def client_packet_to_feed(sock, P):
    """The bytes of a client->server packet that may be fed to the consumer, or None."""
    if not P or looks_like_http(P):
        return None
    if is_login_sock(sock):
        return redact_login(P)
    return P


def _hex_head(h, n=8):
    try:
        return bytes.fromhex(h[:2 * n])
    except ValueError:
        return b''


def sanitize(m):
    """Strip credential-bearing bytes from a message before it is logged or printed.
    Login-socket sends and anything HTTP-shaped keep only their first 2 bytes."""
    sensitive = is_login_sock(m.get('sock', '')) and m.get('tag', '').startswith('SEND')
    is_http = m.get('tag') == 'RECV-HTTP' or looks_like_http(_hex_head(m.get('C', '')))
    if sensitive or is_http:                     # HTTP: by content, not just by port
        for k in ('C', 'P'):
            if k in m:
                m[k] = m[k][:4] + '..redacted'
    return m
