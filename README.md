# CryptographicAlgorithmsSuite
<h2>RSA-OAEP, ElGamal, DES, AES (Rijndael), Diffie Hellman</h2>
<hr />
This repo provides pure Python 3 implementations of various cryptosystems and protocols, authored by me without external dependencies.
<hr />
<h3>Notes</h3>
<b>These implementations are intended for educational purposes only, they are NOT cryptographically secure</b>
<ul>
  <li>
ECB mode of operation is used in DES and AES, parametric mode of operations including CBC, CFB will be introduced later.
  </li>
  <li>
Python's <i>random</i> library was used for PRNG, it uses linear congruential generators which are known to be cryptographically insecure
  </li>
