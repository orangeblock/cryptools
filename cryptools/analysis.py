# -*- coding: utf-8 -*-
import string

from collections import defaultdict
from commons import hamming_bin, chunked, sxor

ASCII_PRINTABLE_FREQS = {
    '\n': 0.02908045733331944, '!': 0.0007948248708319754, ' ': 0.20026065368955764, '#': 8.983102066365002e-08, 
    '"': 0.0007286194086028653, '%': 8.983102066365002e-08, "'": 0.0034381924848805407, '&': 3.683071847209651e-06, 
    ')': 0.0002185588732746605, '(': 0.00021918769041930606, '+': 6.288171446455501e-07, '*': 0.0004286736306069379, 
    '-': 0.005938998269135894, ',': 0.011704263344308288, '/': 0.00038097335863453976, '.': 0.012773971138371034, 
    '1': 0.00532608121514781, '0': 0.005744783602461083, '3': 0.0024439427481752624, '2': 0.002924089553622472, 
    '5': 0.002122886680323377, '4': 0.0019301093099791844, '7': 0.0023404574123707376, '6': 0.0016947520358404212, 
    '9': 0.002559824764831371, '8': 0.002376299989615534, ';': 0.001549315613385972, ':': 0.0013420754487149314, 
    '=': 1.2666173913574653e-05, '<': 4.617314462111611e-05, '?': 0.0009441240271749617, '>': 4.392736910452486e-05, 
    'A': 0.05671014368292093, '@': 2.3356065372549006e-06, 'C': 0.02176228340393453, 'B': 0.01195066983398868, 
    'E': 0.08188097533491699, 'D': 0.028140645195136333, 'G': 0.01255190885529049, 'F': 0.016342688096275856, 
    'I': 0.04845197795331158, 'H': 0.033517750430021094, 'K': 0.005907108256800298, 'J': 0.0013359669393098032, 
    'M': 0.019710812385038752, 'L': 0.030766495760155485, 'O': 0.05332656845860389, 'N': 0.0478192980747775, 
    'Q': 0.0009655038100929104, 'P': 0.014217645471456552, 'S': 0.04791676473219756, 'R': 0.048143677890393935, 
    'U': 0.022709821009894708, 'T': 0.06040731900037478, 'W': 0.012794632273123673, 'V': 0.007006370456661384, 
    'Y': 0.013791487109428197, 'X': 0.001594949771883106, '[': 0.000188914636455656, 'Z': 0.0005081740838942682, 
    ']': 0.0001881959882903468, '\\': 1.7966204132730004e-07, '_': 6.467833487782802e-06, '^': 5.389861239819001e-07, 
    '`': 8.983102066365002e-08, '{': 2.4254375579185508e-06, '}': 2.6050995992458507e-06, '|': 2.964423681900451e-06, 
    '~': 2.6949306199095004e-07, '$': 1e-10, '\r': 1e-10, '\t': 1e-10, '\x0b': 1e-10, '\x0c': 1e-10
}

def chi2_printable(s):
    """
    Run the χ² test on given string for expected distribution 
    of printable characters. Returns the calculated difference.
    """
    obs = defaultdict(int)
    for letter in s:
        if letter not in string.printable:
            return float('inf')
        elif letter in string.ascii_lowercase:
            obs[letter.upper()] += 1
        else:
            obs[letter] += 1
    exp = ASCII_PRINTABLE_FREQS
    return sum([ (obs[c]-(len(s)*exp[c]))**2 / (len(s)*exp[c]) for c in exp ])

def rotN(text, n, alphabet=string.ascii_lowercase):
    """Rotate text by N positions, based on given alphabet.
    
    If a character is not in the alphabet it is kept as is.
    """
    rotated = ''
    for c in text:
        try:
            rotated += alphabet[(alphabet.index(c) + n) % len(alphabet)]
        except ValueError:
            rotated += c
    return rotated

def _xor_guess_key_size(ct, top_results=5, max_key_size=64):
    """Returns a list of the most likely key sizes for a ciphertext 
    xored with a repeating key.
    """
    distances = []
    for ksize in range(2, max_key_size+1):
        chunks = chunked(ct, ksize)
        hammings = [hamming_bin(chunks[i], chunks[i+1])/float(ksize) 
                    for i in range(len(chunks)-1)]
        distances.append((sum(hammings) / len(hammings), ksize))
    return [tup[1] for tup in sorted(distances)][:top_results]

def _xor_key_candidate(ct, keysize):
    blocks = []
    for i in range(keysize):
        group = ct[i::keysize]
        ppts = [(sxor(group, chr(i)*len(group)), i) for i in range(256)]
        # list of -> ((singly_xored_text, xor_char), χ²)
        results = map(lambda x: (x, chi2_printable(x[0])), ppts)
        results = sorted(results, key=lambda x: x[1])
        if results[0][1] == float('inf'):
            # key size doesn't produce anything printable
            return None
        blocks.append(results[0][0])  
    ppt = ''.join([blocks[i%keysize][0][i/len(blocks)] 
                  for i in range(len(ct))])
    pkey = ''.join(map(chr, [b[1] for b in blocks]))
    return (chi2_printable(ppt), pkey, ppt)

def _rot_key_candidate(ct, keysize, alphabet=string.ascii_lowercase):
    """Apply the same principles as repeating key xor to find possible candidate
    for a Vigenere key. It will almost surely return wrong prediction but it may
    be close enough that you can guess the key. Experimental.
    """
    if keysize < 0:
        raise Exception("Invalid keysize; must be positive")
    blocks = []
    for i in range(keysize):
        group = ct[i::keysize]
        ppts = [(rotN(group, i+1, alphabet), alphabet[ (len(alphabet)-i-1)%len(alphabet) ]) 
                for i in range(len(alphabet))]
        # list of -> ((rotated text, key char), χ²)
        results = map(lambda x: (x, chi2_printable(x[0])), ppts)
        results = sorted(results, key=lambda x: x[1])
        if results[0][1] == float('inf'):
            # key size doesn't produce anything printable
            return None
        blocks.append(results[0][0])  
    ppt = ''.join([blocks[i%keysize][0][i/len(blocks)] 
                  for i in range(len(ct))])
    pkey = ''.join([b[1] for b in blocks])
    return (chi2_printable(ppt), pkey, ppt)

# TODO: Filter out duplicate keys
def repeating_xor_decrypt(ct, top_results=5, keysize=None, key=None):
    """Tries to decrypt english text that has been XORed with a repeating key. 

    Accepts the binary ciphertext and, optionally, the keysize if it's known. 
    If no keysize given tries to guess based on hamming binary distance.
    
    Returns a list of (key, plaintext) tuples, up to specified number of top results,
    sorted most to least likely. Can return less if not enough candidates.
    """
    if key:
        return [(key, sxor(ct, key*(len(ct)/len(key))))]
    if keysize:
        if type(keysize) not in [int,float] or keysize < 1:
            raise Exception("Keysize invalid")
        ksizes = [keysize]
    else:
        ksizes = _xor_guess_key_size(ct)
    candidates = []
    for ksize in ksizes:
        candidate = _xor_key_candidate(ct, ksize)
        if candidate:
            candidates.append(candidate)
    return [(c[1], c[2]) for c in sorted(candidates)][:top_results]

def vigenere_decrypt(ct, key, alphabet=string.ascii_lowercase):
    """Decrypts Vigenere ciphertext with given key. Skips over characters
    not in the alphabet.
    """
    if not all([c in alphabet for c in key]):
        raise Exception("Key must only contain alphabet characters")
    ki = 0
    pt = ''
    for c in ct:
        if c not in alphabet:
            pt += c
        else:
            rot = (len(alphabet) - alphabet.index(key[ki])) % len(alphabet)
            pt += alphabet[(alphabet.index(c) + rot) % len(alphabet)]
            ki = (ki + 1) % len(key)
    return pt
