from abc import ABC, abstractmethod

class Signature(ABC):
    @abstractmethod
    def sign(self, messageString):
        pass

    @abstractmethod
    def verify(self, messageString):
        pass