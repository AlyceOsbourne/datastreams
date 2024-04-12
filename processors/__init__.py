import zlib
import abc
import base64
import cryptography.fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import lz4.frame
import os

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
    
class Base64Processor(DataProcessor):
    def process(self, data: bytes) -> bytes:
        return base64.b64encode(data)

    def unprocess(self, data: bytes) -> bytes:
        return base64.b64decode(data)

class AESProcessor(DataProcessor):
    def __init__(self, key: bytes):
        self.key = key
        self.iv = os.urandom(16)
        self.cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=default_backend())

    def process(self, data: bytes) -> bytes:
        encryptor = self.cipher.encryptor()
        return self.iv + encryptor.update(data) + encryptor.finalize()

    def unprocess(self, data: bytes) -> bytes:
        iv = data[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data[16:]) + decryptor.finalize()
    
    @classmethod
    def new(cls):
        return cls(os.urandom(32))

class XORProcessor(DataProcessor):
    def __init__(self, key: bytes):
        self.key = key

    def process(self, data: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(data, self.key * (len(data) // len(self.key) + 1)))

    def unprocess(self, data: bytes) -> bytes:
        return self.process(data)  # XOR is symmetric

    @classmethod
    def new(cls):
        return cls(os.urandom(32))
    
class LZ4Processor(DataProcessor):
    def process(self, data: bytes) -> bytes:
        return lz4.frame.compress(data)

    def unprocess(self, data: bytes) -> bytes:
        return lz4.frame.decompress(data)