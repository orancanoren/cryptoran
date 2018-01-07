import Utils
import random

class RSA:
    def __init__(self):
        self.encryptionExp = None
        self.decryptionExp = None
        self.modulus = None

    def generateKeys(self):
        # 1 - pick primes
        p = Utils.randomLargePrime(256)
        q = Utils.randomLargePrime(256)

        # 2 - compute the modulus
        n = p * q

        # 3 - pick encryption exponent
        e = 2
        totient = (p - 1) * (q - 1)
        while Utils.EEA(e, totient)[0] != 1:
            e = random.randint(2, totient - 1)
        
        # 4 - compute decryption exponent
        d = Utils.multiplicative_inverse(e, totient)

        # DEBUG 
        if ((e * d) % totient != 1):
            print("e and d are NOT inverses")

        self.encryptionExp = e
        self.decryptionExp = d
        self.modulus = n

    def encrypt(self, encodedMessage):
        return pow(encodedMessage, self.encryptionExp, self.modulus)

    def decrypt(self, ciphertext):
        return pow(ciphertext, self.decryptionExp, self.modulus)

crypt = RSA()
crypt.generateKeys()

ciphertext = crypt.encrypt(15)
#print("encryption result:\n", ciphertext)

decrypted = crypt.decrypt(ciphertext)
print("decryption result:\n", decrypted)