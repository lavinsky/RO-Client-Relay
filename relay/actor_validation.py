"""Pure structural validation for decrypted actor/status packet candidates."""
import unicodedata


# Explicit legacy Windows encoding: do not try multiple codecs until one passes.
# Change only after confirming the character encoding used by this server.
ACTOR_NAME_ENCODING = 'cp1252'
# The client can receive NPC names containing printable ASCII symbols such as
# 'Kafra Employee#prt1'. Extended CP1252 remains limited to letters/digits and
# a few typography marks; controls, undefined codepoints and binary garbage fail.
ACTOR_NAME_PUNCTUATION = frozenset(' ‘’“”–—…')


def allowed_actor_name_character(c):
    return (unicodedata.category(c)[0] in ('L', 'N') or
            (c.isascii() and c.isprintable()) or
            c in ACTOR_NAME_PUNCTUATION)


def valid_actor_name(raw):
    """Validate a fixed-width (24-byte) NUL-padded name, never a cipher proof."""
    if len(raw) != 24:
        return False
    name_bytes, sep, padding = raw.partition(b'\x00')
    if not name_bytes or (sep and any(padding)):
        return False
    try:
        name = name_bytes.decode(ACTOR_NAME_ENCODING, errors='strict')
    except UnicodeDecodeError:
        return False
    if name != name.strip():
        return False
    return all(allowed_actor_name_character(c) for c in name)


def actor_name_rejection(raw):
    """Diagnostic category only: never expose the actor's raw name or bytes."""
    if len(raw) != 24:
        return 'invalid-length'
    if not any(raw):
        return 'empty'
    name_bytes, sep, padding = raw.partition(b'\x00')
    if sep and any(padding):
        return 'invalid-padding'
    try:
        name = name_bytes.decode(ACTOR_NAME_ENCODING, errors='strict')
    except UnicodeDecodeError:
        return 'invalid-encoding'
    if name != name.strip():
        return 'edge-whitespace'
    if not all(allowed_actor_name_character(c) for c in name):
        return 'forbidden-character'
    return 'ok'


def fresh_empty_name_actor(pkt, plain):
    """Structural exception for a *freshly observed* 09FF slot, not a generic copy_ok.

    The caller must separately establish same-ring safe preimage, a changed
    post-recv copy in the expected slot, and that the read predates the next recv.
    This function is deliberately never used by ring discovery or scoring.
    """
    return (len(pkt) >= 90 and len(plain) == len(pkt) and
            pkt[:2] == b'\xff\x09' and plain[:4] == pkt[:4] and
            plain != pkt and plain[4] <= 12 and
            0 <= (plain[13] | (plain[14] << 8)) <= 2000 and
            plain[5:9] != b'\x00' * 4 and
            plain[-24:] == b'\x00' * 24)


def valid_actor(P):
    """Does P parse as a plausible 09fd/09ff actor packet?"""
    if len(P) < 60 or P[4] > 12:
        return False
    speed = P[13] | (P[14] << 8)
    name = P[-24:] if len(P) >= 90 else b''
    return 0 <= speed <= 2000 and valid_actor_name(name)


def copy_validation(pkt, P):
    """Boolean-only breakdown of candidate validation; no packet content logged."""
    n = len(pkt)
    same_length = len(P) == n
    changed = P != pkt
    pid = int.from_bytes(pkt[:2], 'little') if n >= 2 else None
    hdrlen = 2 if pid in (0x0229, 0x043f, 0x0983) else 4
    header = n >= 2 and same_length and P[:hdrlen] == pkt[:hdrlen]
    result = {'length_match': same_length, 'header_match': header,
              'body_changed': changed, 'object_type_ok': None,
              'walk_speed_ok': None, 'name_format_ok': None,
              'fixed_gid_ok': None}
    if pid == 0x0983:
        result['fixed_gid_ok'] = (same_length and n == 29 and header and
                                  int.from_bytes(P[4:8], 'little') != 0)
        result['accepted'] = bool(header and changed and result['fixed_gid_ok'])
        return result
    if pid == 0x043f:
        result['fixed_gid_ok'] = (same_length and n == 25 and header and
                                  int.from_bytes(P[4:8], 'little') != 0)
        result['accepted'] = bool(header and changed and result['fixed_gid_ok'])
        return result
    if pid == 0x0229:
        result['fixed_gid_ok'] = (same_length and n == 15 and header and
                                  int.from_bytes(P[2:6], 'little') != 0)
        result['accepted'] = bool(header and changed and result['fixed_gid_ok'])
        return result

    result['object_type_ok'] = len(P) >= 60 and P[4] <= 12
    if len(P) >= 15:
        speed = P[13] | (P[14] << 8)
        result['walk_speed_ok'] = 0 <= speed <= 2000
        result['walk_speed_value'] = speed
    if len(P) >= 60:
        name = P[-24:] if len(P) >= 90 else b''
        result['name_format_ok'] = valid_actor_name(name)
    result['accepted'] = bool(n >= 2 and same_length and changed and header
                              and result['object_type_ok'] and result['walk_speed_ok']
                              and result['name_format_ok'])
    return result
