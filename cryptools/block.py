import os
import itertools

from Crypto.Cipher import AES
from collections import defaultdict
from commons import *

def _block_size_padding(oracle):
    last = oracle('')
    for i in itertools.count(1):
        current = oracle('A'*i)
        if len(current) > len(last):
            last = current
            break
        last = current
    for size in [8, 16, 24, 32]:
        if len(oracle('A'*(i+size))) > len(last):
            return (size, i)

def _prefix_similarity(x, y):
    i = 0
    for xi, yi in zip(x,y):
        if xi != yi:
            break
        i += 1
    return i

def _ecb_prefix_size(oracle, block_size=16):
    last = oracle('')
    target_sim = 0
    for i in itertools.count(1):
        current = oracle('A'*i)
        sim = _prefix_similarity(current, last)
        if sim >= block_size:
            if i == 1:
                target_sim = block_size*(sim/block_size) + block_size
            elif sim > target_sim:
                # check against a non-prefix byte interfering with the filler bytes
                if _prefix_similarity(oracle('B'*i), oracle('B'*(i-1))) > target_sim:
                    prefix_size = block_size*(sim/block_size)-i+1
                    block_end = block_size*(sim/block_size)
                    if i % block_size == 1:
                        block_end -= block_size
                    return (prefix_size, block_end)
        last = current


def pkcs7_pad(data, block_size=16):
    """Calculate and append pkcs7 padding. Block size can be defined dynamically."""
    last_block = data[block_size*(len(data)/block_size):]
    if not last_block:
        return data + chr(block_size)*block_size
    rem = block_size - len(last_block)
    return data + chr(rem)*rem 

def pkcs7_unpad(data, block_size=16):
    """Unpad a pkcs7 padded string. No error handling."""
    return data[:-ord(data[-1])]

def pkcs7_unpad_strict(data, block_size=16):
    """Same as `pkcs7_unpad`, but throw exception on incorrect padding.

    Mostly used to showcase the padding oracle attack.
    """
    pad = data[-1]
    if ord(pad) < 1 or ord(pad) > block_size:
        raise Exception('Invalid padding length')
    for i in range(2, ord(pad)+1):
        if data[-i] != pad:
            raise Exception('Invalid padding character')
    return data[:-ord(pad)]

def is_ecb_mode(ct, block_size=16, threshold=1):
    """Detect if ciphertext is in ECB mode.
    
    Requires at least `threshold` overlapping blocks to be identical.
    Make sure plaintext satisfies this property to get a correct result.
    E.g.: for block_size=16, threshold=1, 48 same consecutive bytes are enough.
    """ 
    blocks = defaultdict(int)
    for i in xrange(0, len(ct)-block_size):
        blocks[ct[i:i+block_size]] += 1
    if sum(blocks.values()) >= len(blocks)+threshold:
        return True
    return False

def ecb_oracle_decrypt(oracle, allowed_chars=None):
    """Given an oracle which returns ciphertexts based on input plaintexts,
    it will decrypt the bytes to the right of the injection point.

    The underlying plaintext must be static; only our input should change.
    The plaintext:ciphertext character ratio must be 1:1.

    `allowed_chars` defines the characters to use for guessing plaintexts.
    Defaults to all 256 byte values.
    """
    if not is_ecb_mode(oracle('A'*48)):
        raise Exception('Encryption mode is not ECB')
    if not allowed_chars:
        allowed_chars = [chr(i) for i in range(256)]
    bsize, padsize = _block_size_padding(oracle)
    psize, pblock_end = _ecb_prefix_size(oracle)
    filler = 'A' * (pblock_end - psize)
    # calculated length of the bytes to be decrypted
    pt_len = len(oracle(filler)[pblock_end:]) - ((padsize - len(filler)) % bsize or bsize)
    pt = ''
    while len(pt) < pt_len:
        found = False
        extra = filler + 'A'*(bsize - (len(pt) % bsize) - 1)
        window_end = pblock_end + bsize * ((len(pt) / bsize) + 1)
        # check the actual ciphertext
        ct = oracle(extra)[pblock_end:window_end]
        # find all ciphertexts of controlled + 1 extra byte
        for c in allowed_chars:
            candidate = extra + pt + c
            if oracle(candidate)[pblock_end:window_end] == ct:
                found = True
                pt += c
                break
        if not found:
            raise Exception('Error decrypting ECB: byte not found')
    return pt

def cbc_padding_oracle_decrypt(ct, oracle, block_size=16):
    """Given a ciphertext and an oracle which returns if input has
    valid pkcs7 padding or not it will decrypt all blocks, except the first.

    `ct` must be encrypted in CBC mode.
    `oracle` must be a function that returns True/False based on valid *pkcs7* padding.
    """
    if len(ct) / block_size < 2:
        raise Exception('At least 2 blocks required')
    if len(ct) % block_size != 0:
        raise Exception('Invalid ciphertext size')
    iblocks = ichunked(ct, block_size)
    prevb = iblocks.next()
    pt = ''
    for block in iblocks:
        known = ''
        while len(known) < block_size:
            prefix_len = block_size - len(known) - 1
            prefix = '\x00'*prefix_len
            pad_len = len(known) + 1
            pad_partial = sxorm(prevb[prefix_len+1:], known, chr(pad_len)*len(known))
            while True:
                hits = 0
                for i in range(256):
                    crafted = prefix + chr(i) + pad_partial + block
                    if oracle(crafted):
                        hits += 1
                        pt_byte = ord(prevb[-pad_len]) ^ (pad_len ^ i)
                        # We try all 256 values for the last byte; for the rest we don't have to.
                        if len(known) > 0:
                            break
                if hits > 1:
                    # Make sure the last byte is \x01 by avoiding prefixes
                    # that generate more than 1 valid paddings in the next block.
                    prefix = os.urandom(prefix_len)
                elif hits == 0:
                    raise Exception('Error decrypting byte: no valid padding found')
                else:
                    known = chr(pt_byte) + known
                    break
        pt += known
        prevb = block
    return pt

def _ctr_counter(nonce, start=0):
    if len(nonce) != 8:
        raise Exception("Nonce must be 8 bytes long")
    ctr = le_cyclic_counter(start)
    def inc():
        return nonce + ctr()
    return inc

def aes_ctr_encrypt(key, pt, nonce=None):
    """Encrypt a plaintext using AES in CTR mode.
    
    If not supplied, generates a random 8 byte nonce each time it is called.
    The counter always starts from 0 and is 8 bytes long.
    The nonce is appended at the start of the ciphertext and
    needs to be present during decryption.
    """
    if nonce is None:
        nonce = os.urandom(8)
    cipher = AES.new(key, AES.MODE_CTR, counter=_ctr_counter(nonce))
    return nonce + cipher.encrypt(pt)

def aes_ctr_decrypt(key, ct):
    """Decrypt a ciphertext that has been encrypted using CTR mode.
    
    The encrypting function must be (or model) `aes_ctr_encrypt`.
    """
    nonce = ct[:8]
    cipher = AES.new(key, AES.MODE_CTR, counter=_ctr_counter(nonce))
    return cipher.decrypt(ct[8:])
