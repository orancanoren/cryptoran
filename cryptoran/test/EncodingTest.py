import unittest
import os, sys
from ..packages import Encoding

class EncodingTest(unittest.TestCase):
    def encodeASCII(self):
        self.assertEqual(549665952565679142563431, Encoding.encodeText(TESTSTRING), 'Encoding text string')
        self.assertNotEqual(549665952565679142563432, Encoding.encodeText(TESTSTRING), 'last digit should be 1 instead of 2')
    
    def decodeASCII(self):
        self.assertEqual(TESTSTRING, Encoding.decodeBits(549665952565679142563431), 'Decoding encoded bits')

if __name__ == '__main__':
    unittest.main()