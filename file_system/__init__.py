from pathlib import Path
from processors import DataProcessor
from signers import Signer

class SignedFile:
    
    def __init__(self, path: str, signer: Signer, processor: DataProcessor=None):
        self.path = path
        self.signer = signer
        self.processor = processor
        self.data_path = Path(path)
        self.sig_path = Path(f"{path}:sig")
    
    def read(self) -> bytes:
        try:
            signature = self.sig_path.read_bytes()
            data = self.data_path.read_bytes()
        except FileNotFoundError:
            raise ValueError("Data not found, unable to verify data integrity")
        if not self.signer.verify(data, signature):
            raise ValueError("Signature mismatch, unable to verify data integrity")
        if self.processor is not None:
            data = self.processor.unprocess(data)
        return data
    def write(self, data: bytes) -> None:
        if self.processor is not None:
            data = self.processor.process(data)
        signature = self.signer.sign(data)
        self.data_path.write_bytes(data)
        self.sig_path.write_bytes(signature)

    def extend(self, data: bytes) -> None:
        self.write(self.read() + data)

    def delete(self) -> None:
        self.data_path.unlink(missing_ok=True)
        
    def exists(self) -> bool:
        return self.data_path.exists()
    
    def create(self, exist_ok: bool=False) -> None:
        self.data_path.touch(exist_ok=exist_ok)
        self.sig_path.touch(exist_ok=exist_ok)

    def __repr__(self):
        return f"{self.__class__.__name__}({self.path!r})"

    def __str__(self):
        return str(self.data_path)
    
    def __fspath__(self):
        return str(self.data_path)
    
    def __get__(self, instance, owner):
        return self.read()
    
    def __set__(self, instance, value):
        self.write(value)
        
    def __delete__(self, instance):
        self.delete()
        
    def __add__(self, other):
        self.extend(other)
        return self
    
    def __bool__(self):
        return self.exists()
