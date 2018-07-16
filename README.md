# cryptoran

[![Build Status](https://travis-ci.org/orancanoren/cryptoran.svg?branch=test)](https://travis-ci.org/orancanoren/cryptoran)

[![PyPI version](https://badge.fury.io/py/cryptoran.svg)](https://badge.fury.io/py/cryptoran)

Cryptoran provides pure Python 3 implementations of various cryptosystems and protocols along with mathematical tools used to build them. No external dependencies!

### why use cryptoran
Cryptoran aims to be a very easy tool to use; providing cryptographic primitives and protocols. A possible use case is to providing security to your client-server application [[example project: pigeon](https://github.com/orancanoren/pigeon)]. An addition of few lines of code will provide security [[_see notes_](#notes)] to your communication.

## Getting Started

Install easily with pip:
```bash
$ pip3 install cryptoran
```

### Command line toolikt

You can use the command line toolkit as `cryptoran command [<args>]`.

__Example__
```bash
$ cryptoran aes cbc myfile.txt -e
Encryption result written to myfile.txt.enc
Key stored in myfile.txt.key

$ cryptoran aes cbc myfile.txt -d -k myfile.txt.key
Output written to myfile.txt.enc.dec
```
Yeah, the filename extensions doesn't seem good. Perhaps you have a great proposal on that; feel free to contribute!
### Python 3 package

Import the package and retrieve the module you want.

```python3
from cryptoran import blockcihper

plaintext = "some ASCII encoded string"
key = 0x89031375397e64eb86ed7d2f924e3100
iv = 0xd0513d87e0be764b41ebb459680485e8

cipher = blockcipher.AES('cbc', key, iv)
ciphertextBlocks = cipher.encrypt(plaintext)
# [0xdf87af9efc6747b7e4c4f6bd1ae46161, 0xaa6dce569cc53c272f6b9303e49d1c4b]

print(cipher.decrypt(ciphertextBlocks)) # this is an ASCII encoded string
```

A concise documentation will be provided in subsequent updates. Proper unit tests haven't been developed yet, version 0.1 will cover them.

## Features

* __Block ciphers__  
Block ciphers support CBC and ECB modes of operations.
  * AES
  * DES
* __Public key crypto__  
Optional support RSA-OAEP is available.
  * RSA
  * Elgamal
* __Key exchange__
  * Diffie-Hellman protocol
* __Signatures__
  * RSA signature

### Known Vulnerabilities

* Python's <i>random</i> library was used for PRNG, it uses linear congruential generators which are known to be cryptographically insecure. The *secrets* module was introduced in Python 3.6 which is claimed to be a module capable of generating cryptographically secure random numbers. Migration to this module will be done soon.

* Diffie-Hellman implementation does not check for the group order; hence it is vulnerable against the __small subgroup confinement attack__

* CBC mode of operation is vulnerable against padding oracle attacks.

## Notes

These implementations are intended for educational purposes only, __they are NOT cryptographically secure__ and they are probably vulnerable against side-channel attacks, some MITM and more.<br/><br/>
