import random

# import shared modules
from .. import Encoding, Utils

# ==============================================
# RSA PKC implementation
# Author: Oran Can Oren
# Email: orancanoren@gmail.com
# ==============================================

class RSA:
    def __init__(self):
        self.encryptionExp = None
        self.decryptionExp = None
        self.modulus = None
        self.OAEPblockSize = None
        self.OAEPk0 = None
        self.OAEPk1 = None

    def generateKeys(self):
        # 1 - pick primes
        p = Utils.randomLargePrime(512)
        q = Utils.randomLargePrime(512)
        while p == q:
            q = Utils.randomLargePrime(512)

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

    def encrypt(self, messageString):
        encodedMessage = Encoding.encodeText(messageString)
        encoder = Encoding.OAEP(500)
        self.OAEPblockSize, self.OAEPk0, self.OAEPk1 = encoder.generateOAEPparams()
        OAEPencodedMessage = encoder.encode(encodedMessage)
        return pow(OAEPencodedMessage, self.encryptionExp, self.modulus)

    def decrypt(self, ciphertext):
        if self.OAEPblockSize == None or self.OAEPk0 == None or self.OAEPk1 == None:
            raise ValueError("OAEP parameters are not ready at time of decryption")

        decrypted = pow(ciphertext, self.decryptionExp, self.modulus)
        OAEPencoder = Encoding.OAEP(self.OAEPblockSize, self.OAEPk0, self.OAEPk1)
        OAEPdecoded = OAEPencoder.decode(decrypted)
        return Encoding.decodeBits(OAEPdecoded)