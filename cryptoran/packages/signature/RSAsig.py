from ..pkc import RSA

class RSAsig:
    def __init__(self, pubKey=None, privKey=None, 
            modulus=None, primeLength=None):
        self.pubKey = None
        self.privKey = None
        self.RSA = RSA(pubKey, privKey, modulus, None, None, )

    def sign(self, document: str) -> str:
        signature = pow(document, self.privKey)
        return signature

    def verify(self, document, signature) -> bool:
        return pow(signature, self.pubKey) == document