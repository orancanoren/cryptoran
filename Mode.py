class Mode:
    def __init__(self, cryptosystem):
        self.crypto = cryptosystem
        self.processedBlocks = [] # result of enc / dec

    def ecb_encrypt(self, blocks):
        for block in blocks:
            encryptedBlock = self.crypto.encryptBlock(block)
            self.processedBlocks.append(encryptedBlock)
        return self.processedBlocks
    
    def ecb_decrypt(self, blocks):
        self.processedBlocks = []
        decryptedBlocks = []
        for block in blocks:
            decryptedBlock = self.crypto.decryptBlock(block)
            self.processedBlocks.append(decryptedBlock)
        return self.processedBlocks

    def cbc_encrypt(self, blocks, IV):

        encryptedBlocks = []
        prevEncBlock = IV
        for block in blocks:
            block = block ^ prevEncBlock
            currentEncryptedBlock = self.encryptBlock(block)
            self.processedBlocks.append(currentEncryptedBlock)
            prevEncBlock = currentEncryptedBlock
        return encryptedBlocks

    def results(self):
        return self.processedBlocks