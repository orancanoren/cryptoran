from abc import ABC, abstractmethod

class BlockCipher(ABC):
    def __init__(self, key, mode):
        self.key = key
        self.mode = mode
        super.__init__()

    @abstractmethod
    def encryptBlock(self, block):
        pass
    
    @abstractmethod
    def decryptBlock(self, block):
        pass

    @abstractmethod
    def blocksToASCII(self, blocks):
        pass