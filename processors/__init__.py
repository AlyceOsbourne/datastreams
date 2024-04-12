import zlib
import pickle

from file_system import DataProcessor

class ZlibProcessor(DataProcessor):
    def process(self, data: bytes) -> bytes:
        return zlib.compress(data)

    def unprocess(self, data: bytes) -> bytes:
        return zlib.decompress(data)

class PickleProcessor(DataProcessor):
    def process(self, data: bytes) -> bytes:
        return pickle.dumps(data)

    def unprocess(self, data: bytes) -> bytes:
        return pickle.loads(data)


class CompoundProcessor(DataProcessor):
    def __init__(self, processors):
        self.processors = processors

    def process(self, data: bytes) -> bytes:
        for processor in self.processors:
            data = processor.process(data)
        return data

    def unprocess(self, data: bytes) -> bytes:
        for processor in reversed(self.processors):
            data = processor.unprocess(data)
        return data