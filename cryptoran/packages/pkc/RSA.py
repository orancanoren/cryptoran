import random

# import shared modules
from .. import Encoding, Utils

# ==============================================
# RSA PKC implementation
# Author: Oran Can Oren
# Email: orancanoren@gmail.com
# ==============================================

class RSA:
    def __init__(self, pubKey=None, privKey=None, modulus=None,
            oaepBlocksize=1024, oaepk0=128, oaepk1=128, primeLength=None,
            oaep=False):
        self.encryptionExp = pubKey
        self.decryptionExp = privKey
        self.modulus = modulus
        self.oaepBlocksize = oaepBlocksize
        self.oaepk0 = oaepk0
        self.oaepk1 = oaepk1
        self.primeLength = primeLength

        self.enableOaep = oaep
        if oaepBlocksize and oaepk0 and oaepk1:
            self.enableOaep = True

    def generateKeys(self):
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

        self.encryptionExp = e
        self.decryptionExp = d
        self.modulus = n
        return ({'encryption exponent': e, 'modulus': n}, {'decryption exponent': d})

    def encrypt(self, messageString):
        encodedMessage = Encoding.encodeText(messageString)
        if self.enableOaep:
            encoder = Encoding.OAEP(self.oaepBlocksize)
            if not (self.oaepk0 and self.oaepk1 and self.oaepBlocksize):
                self.oaepBlocksize, self.oaepk0, self.oaepk1 = encoder.generateOAEPparams()
            encodedMessage = encoder.encode(encodedMessage)
        return pow(encodedMessage, self.encryptionExp, self.modulus)

    def decrypt(self, ciphertext):
        if self.enableOaep and (self.OAEPblockSize == None or self.OAEPk0 == None or self.OAEPk1 == None):
            raise ValueError("OAEP parameters are not ready at time of decryption")

        decrypted = pow(ciphertext, self.decryptionExp, self.modulus)
        if self.enableOaep:
            OAEPencoder = Encoding.OAEP(self.OAEPblockSize, self.OAEPk0, self.OAEPk1)
            decrypted = OAEPencoder.decode(decrypted)
        return Encoding.decodeBits(decrypted)