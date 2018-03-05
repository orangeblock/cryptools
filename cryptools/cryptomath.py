def isqrt(n):
    """Returns the largest integer x for which x * x does not exceed n."""
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

def egcd(b, n):
    """Calculates GCD using Euclid's algorithm, iteratively."""
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
