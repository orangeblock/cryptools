import math
import socket
import struct

LONG_LONG_LIMIT = 18446744073709551615

def _sxor(x,y):
    return ''.join(chr(ord(xi) ^ ord(yi)) for xi,yi in zip(x,y))

def sxor(*xs):
    """Per byte string xor"""
    return ''.join(reduce(_sxor, tup) for tup in zip(*xs))

def d2s(d):
    """Decimal to string"""
    s = hex(d)[2:].rstrip("L")
    if len(s) % 2 != 0:
        s = "0" + s
    return s.decode("hex")

def s2d(s):
    """String to decimal"""
    if not len(s):
        return 0
    return int(s.encode("hex"), 16)

def chunked(l, n):
    """Split l into n-sized chunks"""
    return [l[i:i+n] for i in xrange(0, len(l), n)]

def ichunked(l, n):
    """Lazy iterator of `chunked`"""
    for i in xrange(0, len(l), n):
        yield l[i:i + n]
        
def blen(n):
    """Length of n in bytes. Also handles non-numeric data."""
    try:
        return int(math.ceil(n.bit_length() / 8.0))
    except AttributeError:
        return len(n)

def b2a(b):
    """01110100011001010111001101110100 -> test"""
    return ''.join(chr(int(''.join(x), 2)) for x in zip(*[iter(b)]*8))

def a2b(a):
    """test -> 01110100011001010111001101110100"""
    return ''.join([format(ord(c), '08b') for c in a])

def ip2d(ip):
    """IP to decimal"""
    packed = socket.inet_aton(ip)
    return struct.unpack("!L", packed)[0]

def d2ip(d):
    """Decimal to IP"""
    packed = struct.pack("!L", d)
    return socket.inet_ntoa(packed)

def hamming_bin(x, y):
    """Binary hamming distance of x and y.

    hamming_bin('cat', 'dog') == 9
    """
    return sum(bin(xi^yi).count('1') for xi,yi in zip(bytearray(x),bytearray(y)))

def le_cyclic_counter(start_at=0):
    """8 byte little endian cyclic counter that starts at specified position.

    Position can be supplied in either decimal or 8 byte C long long.
    """
    if type(start_at) == str:
        start_at = struct.unpack('<Q', start_at)[0]
    if start_at < 0:
        raise Exception("Start position cannot be negative")
    if start_at > LONG_LONG_LIMIT:
        raise Exception("Start position cannot exceed 8 byte limit")
    d = {'counter': start_at}
    def inc():
        val = d['counter']
        if val == LONG_LONG_LIMIT:
            d['counter'] = 0
        else:
            d['counter'] += 1
        return struct.pack("<Q", val)
    return inc
