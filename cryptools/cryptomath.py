def iroot(n, r):
    """Computes the integer root of order r of n"""
    u, s = n, n+1
    while u < s:
        s = u
        t = (r-1) * s + n // pow(s, r-1)
        u = t // r
    return s

def isqrt(n):
    """Slightly more efficient than iroot for the special case of r=2"""
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

def egcd(b, n):
    """Calculates GCD iteratively, using Euclid's algorithm."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while n != 0:
        q, b, n = b // n, n, b % n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return  b, x0, y0

def modinv(b, n):
    g, x, _ = egcd(b, n)
    if g == 1:
        return x % n

def crt(n, a):
    """
    Solves the Chinese Remainder Theorem for moduli n and integers a,
    returning the minimal solution x.

    https://en.wikipedia.org/wiki/Chinese_remainder_theorem
    """
    x = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod / n_i
        x += a_i * modinv(p, n_i) * p
    return x % prod
