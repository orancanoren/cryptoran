import unittest
import os, sys

dirname = os.path.dirname
cryptosuitePath = dirname(os.path.join(dirname(dirname(__file__)), '../cryptosuite/'))
sys.path.append(cryptosuitePath)
import Encoding


TESTSTRING = 'teststring'

class EncodingTest(unittest.TestCase):
    def testEncode(self):
        self.assertEqual(549665952565679142563431, Encoding.encodeText(TESTSTRING), 'Encoding text string')
        self.assertNotEqual(549665952565679142563432, Encoding.encodeText(TESTSTRING), 'last digit should be 1 instead of 2')
    
    def testDecode(self):
        self.assertEqual(TESTSTRING, Encoding.decodeBits(549665952565679142563431), 'Decoding encoded bits')

unittest.main()