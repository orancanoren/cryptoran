import datetime
import os, sys
import os, sys
from .Mode import Mode
from .BlockCipher import BlockCipher
from .. import Encoding, Utils

# ==============================================
# Data Encryption Standard (DES) Implementation 
# Author: Oran Can Oren
# Email: orancanoren@gmail.com
# ==============================================

# MARK: class DESround begins
class DESround:
    @staticmethod
    def permute(bits, permutationBox, inputBitLength, outputBitLength):
        permutedBits = 0
        for position, bit in enumerate(permutationBox):
            if bits >> (inputBitLength - bit) & 0b1: #!!!!
                permutedBits |= 1 << (outputBitLength - position - 1)

        return permutedBits

    @staticmethod
    def initialPermutation(block):
        IP = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]

        return DESround.permute(block, IP, 64, 64)

    @staticmethod
    def finalPermutation(block):
        F_Perm = [40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25]
        
        return DESround.permute(block, F_Perm, 64, 64)
    
    @staticmethod
    def expansion(halfBlock):
        expansionBox = [32, 1, 2, 3, 4, 5,
                        4, 5, 6, 7, 8, 9,
                        8, 9, 10, 11, 12, 13,
                        12, 13, 14, 15, 16, 17,
                        16, 17, 18, 19, 20, 21,
                        20, 21, 22, 23, 24, 25,
                        24, 25, 26, 27, 28, 29,
                        28, 29, 30, 31, 32, 1]

        return DESround.permute(halfBlock, expansionBox, 32, 48)

    @staticmethod
    def substitutionBox(keyMixedHalfBlock):
        S_BOX = [
            [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
            ],

            [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
            ],

            [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
            ],

            [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
            ],  

            [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
            ], 

            [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
            ], 

            [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
            ],
            
            [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
            ]
        ]
        substitutionResults = []
        mask = 0b111111
        currentBits = 0
        mixedBlock = int(keyMixedHalfBlock)
        for box in S_BOX[::-1]:
            currentBits = mask & mixedBlock
            mixedBlock >>= 6

            sboxRow = ((currentBits >> 5) << 1) | (currentBits & 0b1)
            sboxCol = (currentBits & 0b011110) >> 1
            substitutionResults.append(box[sboxRow][sboxCol])

        substitutionResult = 0
        for quartet in substitutionResults[::-1]:
            substitutionResult |= quartet
            substitutionResult <<= 4
        substitutionResult >>= 4

        return substitutionResult

    @staticmethod
    def permutationBox(substitutionResult):
        P = [16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25]

        return DESround.permute(substitutionResult, P, 32, 32)

    @staticmethod
    def feistelFunction(rightHalf, roundKey):
        # 1 - expansion phase
        expandedRightHalf = DESround.expansion(rightHalf)

        # 2 - key mixing phase
        keyMixedExpandedHalfBlock = expandedRightHalf ^ roundKey

        # 3 - substitution phase
        substitutionResults = DESround.substitutionBox(keyMixedExpandedHalfBlock)

        # 4 - permutation phase
        permuted = DESround.permutationBox(substitutionResults)

        return permuted

    @staticmethod
    def applyRound(leftHalf, rightHalf, roundKey):
        f = DESround.feistelFunction(rightHalf, roundKey)

        newRigtHalf = leftHalf ^ f

        permutedBlock = (rightHalf << 32) + newRigtHalf

        return permutedBlock
    # MARK: class DESround ends

class DES(BlockCipher):
    def __init__(self, mode, key, IV):
        super().__init__(64)
        self.key = key
        if self.key == None:
            self.key = self.generateRandomKey()
        self.mode = Mode(self, mode, IV)
        self.IV = IV
        self.roundKeys = None

    def _generateRoundKeys(self):
        self.roundKeys = [0]*16
        shift = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

        # initial permutation on key
        initKeyPerm = [57, 49, 41, 33, 25, 17, 9,
                    1, 58, 50, 42, 34, 26, 18,
                    10, 2, 59, 51, 43, 35, 27,
                    19, 11, 3, 60, 52, 44, 36,
                    63, 55, 47, 39, 31, 23, 15,
                    7, 62, 54, 46, 38, 30, 22,
                    14, 6, 61, 53, 45, 37, 29,
                    21, 13, 5, 28, 20, 12, 4]

        # permutation applied for each round
        shiftRoundPerm = [14, 17, 11, 24, 1, 5, 3, 28,
                        15, 6, 21, 10, 23, 19, 12, 4,
                        26, 8, 16, 7, 27, 20, 13, 2,
                        41, 52, 31, 37, 47, 55, 30, 40,
                        51, 45, 33, 48, 44, 49, 39, 56,
                        34, 53, 46, 42, 50, 36, 29, 32]

        def shiftBits(bits, shiftAmount):
            # <bits> should be 28-bits long
            # 1 - check most significant bits
            # 2 - clear most significant bits, shift by appropriate amount
            # and place previous MSB to LSB
            if shiftAmount == 1:
                msb = (bits >> 27) | 0b0
                bits &= 2**27 - 1
                bits <<= 1
                bits |= msb
            else:
                msb = (bits >> 26) | 0b00
                bits &= 2**26 - 1
                bits <<= 2
                bits |= msb
            return bits

        permutedKey = DESround.permute(self.key, initKeyPerm, 64, 56)
        leftHalfKey = permutedKey >> 28
        rightHalfKey = permutedKey & (2**28 - 1)
        for i in range(16): # generate a 48-bit key for each round
            leftHalfKey = shiftBits(leftHalfKey, shift[i])
            rightHalfKey = shiftBits(rightHalfKey, shift[i])

            self.roundKeys[i] = DESround.permute((leftHalfKey << 28) | rightHalfKey, shiftRoundPerm, 56, 48)

    def _processBlock(self, block, roundKeys):
        # 1 - obtain the initial permutation
        block = DESround.initialPermutation(block)
        # 2 - apply 16 rounds of DES
        for i in range(16):
            leftHalf = block >> 32
            rightHalf = block & (2**32 - 1)
            block = DESround.applyRound(leftHalf, rightHalf, roundKeys[i])

        # apply the final permutation to the block having its left and right halves switched
        leftHalf = block >> 32
        rightHalf = block & (2**32 - 1)

        # 3 - apply final permutation
        processedBlock = DESround.finalPermutation((rightHalf << 32) | leftHalf)

        return processedBlock

    def encryptBlock(self, block: int) -> int:
        # use the standard round keys (not reversed)
        if not self.roundKeys:
            self._generateRoundKeys()
        return self._processBlock(block, self.roundKeys)

    def decryptBlock(self, block: int) -> int:
        # use round keys in reversed order
        if not self.roundKeys:
            self._generateRoundKeys()
        return self._processBlock(block, self.roundKeys[::-1])

    def encrypt(self, messageString: str) -> list:
        blocks = Encoding.divideToBlocks(messageString, 64) # DES uses 64-bit plaintext blocks
        encryptedBlocks = self.mode.encrypt(blocks)
        return encryptedBlocks

    def decrypt(self, blocks: list) -> str:
        decrypted = self.mode.decrypt(blocks)
        decryptedString = Encoding.blocksToASCII(decrypted)
        return decryptedString

if __name__ == "__main__":
    print("DES Encryption tool")

    # Get the mode of operation
    mode = input("Enter the mode of operation (CBC, ECB):\n>> ")
    iv = None
    if mode == 'CBC':
        iv = input('Enter the initial vector for CBC mode (leave blank for random)\n>> ')
        if iv == '':
            iv = Utils.randomNumber(56)
            print('IV:', hex(iv))

   # Get the key 
    DESkey = input("Enter the 64-bit DES key (leave blank for random key generation):\n>> ")
    if DESkey == "":
        DESkey = Utils.randomNumber(64)
        print("DES key:", hex(DESkey))

    # Instantiate the AES class
    crypt = DES(DESkey, mode, iv)

    messageString = input("Enter text\n>> ")
    encryptedBlocks = crypt.encrypt(messageString)
    for i, block in enumerate(encryptedBlocks):
        print(f"encrypted block {i}: {hex(block)}")

    decryptionResult = crypt.decrypt(encryptedBlocks)
    print("Decryption result:\n" + decryptionResult)