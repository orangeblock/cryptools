import itertools
import cryptomath as m

from Crypto.PublicKey import RSA

def construct_private(p, q, e):
    """Constructs the RSA private key, using p, q and e."""
    d = m.modinv(e, (p-1)*(q-1))
    return RSA.construct((long(p*q), long(e), long(d)))

def common_factor_attack(pub1, pub2):
    gcd, _, _ = m.egcd(pub1.n, pub2.n)
    if gcd > 1:
        return (construct_private(gcd, pub1.n/gcd, pub1.e),
                construct_private(gcd, pub2.n/gcd, pub2.e))
