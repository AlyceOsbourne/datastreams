from pathlib import Path
import abc

class Signer(abc.ABC):
    @abc.abstractmethod
    def sign(self, data: bytes) -> bytes:
        pass

    @abc.abstractmethod
    def verify(self, data: bytes, signature: bytes) -> bool:
        pass
    
class DataProcessor(abc.ABC):
    @abc.abstractmethod
    def process(self, data: bytes) -> bytes:
        pass

    @abc.abstractmethod
    def unprocess(self, data: bytes) -> bytes:
        pass
    
    
class SignedFile:
    def __init__(self, path: str, signer: Signer, processor: DataProcessor):
        self.path = path
        self.signer = signer
        self.processor = processor
        self.data_path = Path(path)
        self.sig_path = Path(f"{path}:sig")
    
    def write(self, data: bytes) -> None:
        if self.processor is not None:
            data = self.processor.process(data)
        signature = self.signer.sign(data)
        self.data_path.write_bytes(data)
        self.sig_path.write_bytes(signature)

    def read(self) -> bytes:
        data = self.data_path.read_bytes()
        signature = self.sig_path.read_bytes()
        if not self.signer.verify(data, signature):
            raise ValueError("Signature mismatch, unable to verify data integrity")
        if self.processor is not None:
            data = self.processor.unprocess(data)
        return data

    def delete(self) -> None:
        self.data_path.unlink(missing_ok=True)

    def __repr__(self):
        return f"{self.__class__.__name__}({self.path!r})"

    def __str__(self):
        return str(self.data_path)
