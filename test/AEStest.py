import unittest
import os, sys

dirname = os.path.dirname
cryptosuitePath = dirname(os.path.join(dirname(dirname(__file__)), '../cryptosuite/'))
BlockCipherPath = dirname(os.path.join(dirname(dirname(__file__)), '../cryptosuite/BlockCiphers'))
sys.path.append(cryptosuitePath)
sys.path.append(BlockCipherPath)

from BlockCiphers.AES import AES

class AEStest(unittest.TestCase):
    def testECBEncryption(self): # more of an integration test rather than a unit test
        cipher = AES(0xB054A58D4D929D2F58E82110D50BB9B2, 'ECB')
        self.assertEqual([0xCA6A0D32671568D404E251C1BEF9829], cipher.encrypt('teststring'))
        

if __name__ == '__main__':
    unittest.main()