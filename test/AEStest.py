import unittest
import os, sys

from ..cryptosuite.BlockCiphers import AES

class AEStest(unittest.TestCase):
    def testECBEncryption(self): # more of an integration test rather than a unit test
        cipher = AES(0xB054A58D4D929D2F58E82110D50BB9B2, 'ECB')
        self.assertEqual([0xCA6A0D32671568D404E251C1BEF9829], cipher.encrypt('teststring'))