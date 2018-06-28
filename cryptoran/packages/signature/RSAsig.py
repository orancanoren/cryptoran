from ..pkc import RSA
from ..Encoding import encodeText, decodeBits

class RSAsig:
    def __init__(self, pubKey=None, privKey=None, modulus=None, primeLength=None):
        self.RSA = RSA(pubKey, privKey, modulus, primeLength, asciiEncode=False)

    def  generateKeys(self):
        return self.RSA.generateKeys()

    def sign(self, document: str) -> str:
        encodedDoc = encodeText(document)
        signature = self.RSA.decrypt(encodedDoc)
        return signature

    def verify(self, document: str, signature: int) -> bool:
        signat = decodeBits(self.RSA.encrypt(signature))
        return signat == document