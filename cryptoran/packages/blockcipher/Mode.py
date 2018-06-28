# ===================================================
# Mode of Operation Implementations for Block Ciphers
# Author: Oran Can Oren
# Email: orancanoren@gmail.com
# ===================================================
import types

availableModes = ['ecb', 'cbc']

class Mode:
    '''Implements encryption and decryption functions for specified mode of operations.
    Available modes: ECB, CBC
    '''

    def __init__(self, cryptosystem, mode, IV):
        if mode not in availableModes:
            errmsg = ' is not an available mode!'
            if type(mode) == str:
                errmsg = mode + errmsg
            else:
                errmsg = 'provided mode (of type ' + str(type(mode)) + ')' + errmsg
            raise Exception(errmsg)
        self._crypto = cryptosystem
        self._mode = mode
        self._iv = IV
        if mode in ['cbc'] and not self._iv:
            self._iv = cryptosystem.generateRandomKey()
        
    @staticmethod
    def _blocksAreValid(blocks):
        if type(blocks) != list or blocks == []:
            print('blocks are:', blocks)
            return False
        return True

    def getIV():
        return self._iv

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

    def _cbcEncrypt(self, blocks):
        if not Mode._blocksAreValid(blocks):
            raise Exception('Invalid blocks received')

        encryptedBlocks = []
        prevEncBlock = self._iv
        for block in blocks:
            block = block ^ prevEncBlock
            currentEncryptedBlock = self._crypto.encryptBlock(block)
            encryptedBlocks.append(currentEncryptedBlock)
            prevEncBlock = currentEncryptedBlock
        return encryptedBlocks

    def _cbcDecrypt(self, blocks):
        if not Mode._blocksAreValid(blocks):
            raise Exception('Invalid blocks received')

        decryptedBlocks = []
        for i in range(len(blocks))[:0:-1]:
            p_i = self._crypto.decryptBlock(blocks[i]) ^ blocks[i - 1]
            decryptedBlocks.insert(0, p_i)
        decryptedBlocks.insert(0, self._crypto.decryptBlock(blocks[0]) ^ self._iv)
        return decryptedBlocks

    def encrypt(self, blocks):
        if self._mode == 'ecb':
            return self._ecbEncrypt(blocks)
        elif self._mode == 'cbc':
            return self._cbcEncrypt(blocks)

    def decrypt(self, blocks):
        if self._mode == 'ecb':
            return self._ecbDecrypt(blocks)
        elif self._mode == 'cbc':
            return self._cbcDecrypt(blocks)