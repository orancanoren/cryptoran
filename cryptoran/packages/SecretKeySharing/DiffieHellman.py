import random
from .. import Encoding, Utils

class DiffieHellman:
    def __init__(self, prime = None, generator = None):
        self.secret = None
        self.expSecret = None
        self.prime = prime
        self.generator = generator
        self.sharedKey = None
        self.correspondentSecret = None # used only for demonstration
    
    def generateSecret(self):
        if self.prime == None:
            # group and its generator is initialized by this party
            group = Utils.getGroupWithGenerator(256)
            self.prime = group[0]
            self.generator = group[1]
            print(f"Group properties\nPrime: {hex(self.prime)}\nGenerator: {hex(self.generator)}\n")

        self.secret = random.randint(2, self.prime - 1)
        self.expSecret = pow(self.generator, self.secret , self.prime)
        print(f"this party sends: {hex(self.expSecret)}")

    def generateSharedKey(self, keyFromOtherEnd = None):
        if keyFromOtherEnd == None:
            # randomly generate some number to simulate as if
            # corresponding party has sent g^{secret}
            keyFromOtherEnd = random.randint(2, self.prime  - 1)
            self.correspondentSecret = keyFromOtherEnd
        
        self.sharedKey = pow(self.expSecret, keyFromOtherEnd, self.prime)
    
    def verifySharedKey(self):
        if self.correspondentSecret == None or self.sharedKey == None:
            return
        
        correspondentExp = pow(self.expSecret, self.correspondentSecret, self.prime)
        if self.sharedKey == correspondentExp:
            return True
        return False