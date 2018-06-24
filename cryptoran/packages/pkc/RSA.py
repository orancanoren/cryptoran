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
            primeLength=None, oaepBlocksize=1024, oaepk0=128, oaepk1=128,
            oaep=False, asciiEncode = True):
        super().__init__(pubKey, privKey, modulus, primeLength)
        self.oaepBlocksize = oaepBlocksize
        self.oaepk0 = oaepk0
        self.oaepk1 = oaepk1
        self.enableOaep = oaep
        self.asciiEncode = asciiEncode

    def generateKeys(self) -> tuple:
        # 1 - pick primes
        if not self.pubKey or not self.privKey:
            p = Utils.randomLargePrime(self.primeLength // 2)
            q = Utils.randomLargePrime(self.primeLength // 2)
            while p == q:
                q = Utils.randomLargePrime(self.primeLength // 2)

        # 2 - compute the modulus
        if not self.modulus:
            n = p * q
            totient = (p - 1) * (q - 1)

        # 3 - pick encryption exponent
        if not self.pubKey:
            e = 2
            while Utils.EEA(e, totient)[0] != 1:
                e = random.randint(2, totient - 1)

        # 4 - compute decryption exponent
        if not self.privKey:
            d = Utils.multiplicative_inverse(e, totient)

        self.pubKey = e
        self.privKey = d
        self.modulus = n
        return ((e, n), (d, ))

    def encrypt(self, messageString) -> int:
        if self.asciiEncode:
            messageString = Encoding.encodeText(messageString)
        if self.enableOaep:
            encoder = Encoding.OAEP(self.oaepBlocksize)
            if not (self.oaepk0 and self.oaepk1 and self.oaepBlocksize):
                self.oaepBlocksize, self.oaepk0, self.oaepk1 = encoder.generateOAEPparams()
            messageString = encoder.encode(messageString)
        return pow(messageString, self.pubKey, self.modulus)

    def decrypt(self, ciphertext) -> str:
        if self.enableOaep and (self.oaepBlocksize == None or self.oaepk0 == None or self.oaepk1 == None):
            raise ValueError("OAEP parameters are not ready at time of decryption")

        decrypted = pow(ciphertext, self.privKey, self.modulus)
        if self.enableOaep:
            OAEPencoder = Encoding.OAEP(self.oaepBlocksize, self.oaepk0, self.oaepk1)
            decrypted = OAEPencoder.decode(decrypted)
        if self.asciiEncode:
            decrypted = Encoding.decodeBits(decrypted)
        return decrypted