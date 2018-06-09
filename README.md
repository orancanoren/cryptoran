# CryptographicAlgorithmsSuite
<h2>RSA-OAEP, ElGamal, DES, AES (Rijndael), Diffie Hellman</h2>
<hr />
This repo provides pure Python 3 implementations of various cryptosystems and protocols, authored by me without external dependencies.
<hr />
<h3>Notes</h3>
<b>These implementations are intended for educational purposes only, they are NOT cryptographically secure and they are probably vulnerable against side-channel attacks.</b>
<ul>
  <li>
    ECB and CBC modes of operation are currently supported for block ciphers.
  </li>
  <li>
Python's <i>random</i> library was used for PRNG, it uses linear congruential generators which are known to be cryptographically insecure. The <i>secrets</i> module was introduced in Python 3.6 which is claimed to be a module capable of generating cryptographically secure random numbers. Migration to this module will be done soon.
  </li>
