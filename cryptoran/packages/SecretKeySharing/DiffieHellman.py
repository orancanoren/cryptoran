import random
from .. import Encoding, Utils

class DiffieHellman:
    def __init__(self, prime = None, generator = None, primeLength = None):
        self.secret = None
        self.expSecret = None
        self.prime = prime
        self.generator = generator
        self.sharedKey = None
        self.primeLength = primeLength
    
    def generateSecret(self):
        if not self.prime:
            # group and its generator is initialized by this party
            self.prime, self.generator = Utils.getGroupWithGenerator(self.primeLength)

        self.secret = random.randint(2, self.prime - 1)
        self.expSecret = pow(self.generator, self.secret , self.prime)

        # [prime, generator, generator ^ secret]
        return [self.prime, self.generator, self.expSecret]

    def generateSharedKey(self, keyFromOtherEnd):
        if not self.secret:
            raise Exception('DH secret not set at time of shared key generation')
        self.sharedKey = pow(keyFromOtherEnd, self.secret, self.prime)
        return self.sharedKey