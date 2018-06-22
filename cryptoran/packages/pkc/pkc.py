from abc import ABC, abstractmethod

class PKC:
    def __init__(self, pubKey=None, privKey=None, modulus=None, primeLength=None):
        if not (modulus and privKey and pubKey) and not primeLength:
            raise Exception('Either prime length or keys must be provided')
        self.pubKey = pubKey
        self.privKey = privKey
        self.modulus = modulus
        self.primeLength = primeLength

    @abstractmethod
    def generateKeys(self) -> tuple:
        pass

    @abstractmethod
    def encrypt(self, msg: str) -> int:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: int) -> str:
        pass