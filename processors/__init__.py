import zlib
import cryptography.fernet
import abc
class DataProcessor(abc.ABC):
    @abc.abstractmethod
    def process(self, data: bytes) -> bytes:
        pass

    @abc.abstractmethod
    def unprocess(self, data: bytes) -> bytes:
        pass
class CompoundProcessor(DataProcessor):
    def __init__(self, *processors):
        self.processors = processors

    def process(self, data: bytes) -> bytes:
        for processor in self.processors:
            data = processor.process(data)
        return data

    def unprocess(self, data: bytes) -> bytes:
        for processor in reversed(self.processors):
            data = processor.unprocess(data)
        return data
class ZlibProcessor(DataProcessor):
    def process(self, data: bytes) -> bytes:
        return zlib.compress(data)

    def unprocess(self, data: bytes) -> bytes:
        return zlib.decompress(data)
class FernetProcessor(DataProcessor):
    def __init__(self, key: bytes):
        self.key = key
        self.fernet = cryptography.fernet.Fernet(key)
        
    def process(self, data: bytes) -> bytes:
        return self.fernet.encrypt(data)
    
    def unprocess(self, data: bytes) -> bytes:
        return self.fernet.decrypt(data)
    
    @classmethod
    def new(cls):
        return cls(cryptography.fernet.Fernet.generate_key())