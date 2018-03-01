import struct

from impl import sha1 as _sha1, md4 as _md4
from commons import chunked

def _sha1_pad(ptlen):
    return b'\x80' + b'\x00' * ((56 - (ptlen + 1) % 64) % 64) + \
           struct.pack(b'>Q', ptlen*8)

def _sha1_extend(mac, pt, extension, prefix_len):
    state = tuple([long(chunk, 16) for chunk in chunked(mac, 8)])
    pad = _sha1_pad(prefix_len+len(pt))
    crafted_m = pt + pad + extension
    crafted_h = _sha1(extension, state, prefix_len+len(crafted_m)).hexdigest()
    return (crafted_m, crafted_h)

def sha1_extend(mac, pt, extension, oracle=None, prefix_len=None, min_prefix=0, max_prefix=999):
    """Extend given sha1 hex digest `mac` for plaintext `pt` with given `extension`.

    It requires a pre-defined prefix length to be specified, or an oracle
    that returns True/False based on its validity. You can also set the 
    min/max prefix lenghts the function tests for, in the case it's unknown.

    The oracle receives the message that was crafted and the hex digest, in that order, all required.
    
    Returns a tuple of the successful message/digest. If no prefix length specified
    and oracle never returned postive result it returns None.
    """
    if prefix_len is None and oracle is None:
        raise Exception("Invalid state: Need prefix length or oracle")
    if prefix_len is not None:
        return _sha1_extend(mac, pt, extension, prefix_len)
    else:
        for i in xrange(min_prefix, max_prefix+1):
            crafted_m, crafted_h = _sha1_extend(mac, pt, extension, i)
            if oracle(crafted_m, crafted_h):
                return (crafted_m, crafted_h)

def _md4_pad(ptlen):
    return b'\x80' + b'\x00' * ((56 - (ptlen + 1) % 64) % 64) + \
           struct.pack(b'<Q', ptlen*8)

def _md4_extend(mac, pt, extension, prefix_len):
    state = [struct.unpack('<I', chunk.decode('hex'))[0] for chunk in chunked(mac, 8)]
    pad = _md4_pad(prefix_len+len(pt))
    crafted_m = pt + pad + extension
    crafted_h = _md4(extension, state, prefix_len+len(crafted_m)).hexdigest()
    return (crafted_m, crafted_h)

def md4_extend(mac, pt, extension, oracle=None, prefix_len=None, min_prefix=0, max_prefix=999):
    """Extend given md4 hex digest `mac` for plaintext `pt` with given `extension`.

    It requires a pre-defined prefix length to be specified, or an oracle
    that returns True/False based on its validity. You can also set the 
    min/max prefix lenghts the function tests for, in the case it's unknown.

    The oracle receives the message that was crafted and the hex digest, in that order, all required.
    
    Returns a tuple of the successful message/digest. If no prefix length specified
    and oracle never returned postive result it returns None.
    """
    if prefix_len is None and oracle is None:
        raise Exception("Invalid state: Need prefix length or oracle")
    if prefix_len is not None:
        return _md4_extend(mac, pt, extension, prefix_len)
    else:
        for i in xrange(min_prefix, max_prefix+1):
            crafted_m, crafted_h = _md4_extend(mac, pt, extension, i)
            if oracle(crafted_m, crafted_h):
                return (crafted_m, crafted_h)
