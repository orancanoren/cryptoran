import random

# import shared modules
from .. import Encoding, Utils
from .pkc import PKC

# ==============================================
# RSA PKC implementation
# Author: Oran Can Oren
# Email: orancanoren@gmail.com
# ==============================================

class RSA(PKC):
    def __init__(self, pubKey=None, privKey=None, modulus=None,
            oaepBlocksize=1024, primeLength=None, oaepk0=128, oaepk1=128,
            oaep=False):
        super().__init__(pubKey, privKey, modulus, primeLength)
        self.oaepBlocksize = oaepBlocksize
        self.oaepk0 = oaepk0
        self.oaepk1 = oaepk1
        self.enableOaep = oaep

    def generateKeys(self) -> tuple:
        # 1 - pick primes
        p = Utils.randomLargePrime(self.primeLength // 2)
        q = Utils.randomLargePrime(self.primeLength // 2)
        while p == q:
            q = Utils.randomLargePrime(self.primeLength // 2)

        # 2 - compute the modulus
        n = p * q
        totient = (p - 1) * (q - 1)

        # 3 - pick encryption exponent
        e = 2
        while Utils.EEA(e, totient)[0] != 1:
            e = random.randint(2, totient - 1)

        # 4 - compute decryption exponent
        d = Utils.multiplicative_inverse(e, totient)

        print('e x d mod totient(n):', (e * d) % totient)

        self.pubKey = e
        self.privKey = d
        self.modulus = n
        return ({'encryption exponent': e, 'modulus': n}, {'decryption exponent': d})

    def encrypt(self, messageString) -> int:
        encodedMessage = Encoding.encodeText(messageString)
        if self.enableOaep:
            encoder = Encoding.OAEP(self.oaepBlocksize)
            if not (self.oaepk0 and self.oaepk1 and self.oaepBlocksize):
                self.oaepBlocksize, self.oaepk0, self.oaepk1 = encoder.generateOAEPparams()
            encodedMessage = encoder.encode(encodedMessage)
        return pow(encodedMessage, self.pubKey, self.modulus)

    def decrypt(self, ciphertext) -> str:
        if self.enableOaep and (self.oaepBlocksize == None or self.oaepk0 == None or self.oaepk1 == None):
            raise ValueError("OAEP parameters are not ready at time of decryption")

        decrypted = pow(ciphertext, self.privKey, self.modulus)
        if self.enableOaep:
            OAEPencoder = Encoding.OAEP(self.oaepBlocksize, self.oaepk0, self.oaepk1)
            decrypted = OAEPencoder.decode(decrypted)
        print('decrypted raw:', decrypted)
        return Encoding.decodeBits(decrypted)