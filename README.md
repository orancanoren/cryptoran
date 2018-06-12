# cryptoran
<h2>A crypto library implemented in pure Python 3</h2>
Cryptoran provides pure Python 3 implementations of various cryptosystems and protocols. No external dependencies!

## Usage

```python3
from cryptoran.cryptosuite.BlockCiphers import AES
plaintext = "this is an ASCII encoded string"
key = 92837429324
iv = 20348120348
cipher = AES('cbc', key, iv)
ciphertextBlocks = cipher.encrypt(plaintext)
# [0x2619c77c7a108d0f001df29682a04a19, 0xa331d003481363af4c860883ecbcb34d]

print(cipher.decrypt(ciphertextBlocks)) # this is an ASCII encoded string
```

## Features

* __Block ciphers__  
Block ciphers support CBC and ECB modes of operation.
  * AES
  * DES
* __Public key crypto__  
Optional support RSA-OAEP is available.
  * RSA
  * Elgamal
* __Key exchange__
  * Diffie-Hellman protocol

## Notes

__These implementations are intended for educational purposes only, they are NOT cryptographically secure and they are probably vulnerable against side-channel attacks, some MITM and more.__<br/><br/>

### Known Vulnerabilities

* Python's <i>random</i> library was used for PRNG, it uses linear congruential generators which are known to be cryptographically insecure. The *secrets* module was introduced in Python 3.6 which is claimed to be a module capable of generating cryptographically secure random numbers. Migration to this module will be done soon.

* Diffie-Hellman implementation does not check for the group order; hence it is vulnerable against the __small subgroup confinement attack__
