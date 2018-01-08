import Utils
import random

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

    def generateKeys(self):
        # 1 - pick primes
        p = Utils.randomLargePrime(512)
        q = Utils.randomLargePrime(512)
        while p == q:
            q = Utils.randomLargePrime(512)

        # 2 - compute the modulus
        n = p * q
        print(f"p: {p}\nq: {q}")
        totient = (p - 1) * (q - 1)

        # 3 - pick encryption exponent
        e = 2
        while Utils.EEA(e, totient)[0] != 1:
            e = random.randint(2, totient - 1)

        # 4 - compute decryption exponent
        d = Utils.multiplicative_inverse(e, totient)

        self.e = e
        self.d = d
        self.n = n
        self.p = p
        self.q = q

    def encrypt(self, messageString):
        encodedMessage = Utils.encodeText(messageString)
        return pow(encodedMessage, self.e, self.n)

    def decrypt(self, ciphertext):
        decrypted = pow(ciphertext, self.d, self.n)
        return Utils.decodeBits(decrypted)

crypt = RSA()
crypt.generateKeys()

ciphertext = crypt.encrypt(input("Enter text\n>> "))
print("encryption result:\n", hex(ciphertext))

decrypted = crypt.decrypt(ciphertext)
print("decryption result:\n", decrypted)