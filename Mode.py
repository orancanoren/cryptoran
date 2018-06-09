# ===================================================
# Mode of Operation Implementations for Block Ciphers
# Author: Oran Can Oren
# Email: orancanoren@gmail.com
# ===================================================
import types

class Mode:
    '''Implements encryption and decryption functions for specified mode of operations.
    Available modes: ECB, CBC
    '''

    def __init__(self, cryptosystem, mode):
        self._crypto = cryptosystem
        self._mode = mode
        
    @staticmethod
    def _blocksAreValid(blocks):
        if type(blocks) != list or blocks == []:
            print('blocks are:', blocks)
            return False
        return True

    def _ecbEncrypt(self, blocks):
        if not Mode._blocksAreValid(blocks):
            raise Exception('Invalid blocks received')
        encryptedBlocks = []
        for block in blocks:
            encryptedBlock = self._crypto.encryptBlock(block)
            encryptedBlocks.append(encryptedBlock)
        return encryptedBlocks
    
    def _ecbDecrypt(self, blocks):
        if not Mode._blocksAreValid(blocks):
            raise Exception('Invalid blocks received')
        decryptedBlocks = []
        decryptedBlocks = []
        for block in blocks:
            decryptedBlock = self._crypto.decryptBlock(block)
            decryptedBlocks.append(decryptedBlock)
        return decryptedBlocks

    def _cbcEncrypt(self, blocks, IV):
        if not Mode._blocksAreValid(blocks):
            raise Exception('Invalid blocks received')

        encryptedBlocks = []
        prevEncBlock = IV
        for block in blocks:
            block = block ^ prevEncBlock
            currentEncryptedBlock = self._crypto.encryptBlock(block)
            encryptedBlocks.append(currentEncryptedBlock)
            prevEncBlock = currentEncryptedBlock
        return encryptedBlocks

    def _cbcDecrypt(self, blocks, IV):
        if not Mode._blocksAreValid(blocks):
            raise Exception('Invalid blocks received')

        decryptedBlocks = []
        for i in range(len(blocks))[1::-1]:
            currentDecryptedBlock = self._crypto.decryptBlock(blocks[i]) ^ blocks[i - 1]
            decryptedBlocks.insert(0, currentDecryptedBlock)
        decryptedBlocks.insert(0, self._crypto.decryptBlock(blocks[0]))
        return decryptedBlocks

    def encrypt(self, blocks, IV = None):
        if self._mode == 'ECB':
            return self._ecbEncrypt(blocks)
        elif self._mode == 'CBC':
            return self._cbcEncrypt(blocks, IV)

    def decrypt(self, blocks, IV = None):
        if self._mode == 'ECB':
            return self._ecbDecrypt(blocks)
        elif self._mode == 'CBC':
            return self._cbcDecrypt(blocks, IV)