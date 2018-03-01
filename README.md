### Description 
A toolbox for tinkering with cryptographic implementations. 

It came about as a side effect of working through the cryptopals challenges. It's definitely still a work in progress and nothing here is final. Feel free to use it as you see fit.

### Installation
Currently this library requires PyCrypto to be installed. This might change in the future but for now there are a couple of functions in there that need it and I haven't made them optional.  

If you want to install this using setup.py you can run (from the root of this repo):
```
python setup.py install
```

My suggestion is to install this using pip. First run:
```
python setup.py sdist
```
which will create a `dist` directory with the packaged archive inside. Then run:
```
pip install dist/<archive>
```

### Modules
The following modules currently exist:

#### cryptools.analysis
Some basic tools for doing statistical ciphertext analysis: chi squared test, rot, repeating key xor.

#### cryptools.block
Tools that deal with weak block cipher implementations: ECB mode detection, ECB/CBC oracle decryption.

#### cryptools.commons
Frequently used utility functions.

#### cryptools.hash
Length extension attacks against sha1 and md4. The tweaked hash algorithms themselves are in **cryptools.impl**.
