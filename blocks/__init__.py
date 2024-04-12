from functools import reduce
import hashlib
from pickle import dumps, loads
from typing import Any, Callable, Iterator, MutableMapping, NoReturn

class HashedDataBlock(MutableMapping):
    __block_hash__: Callable[[bytes], bytes] = "sha256"
    
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self) -> str:
        return repr(self.__dict__)

    def __iter__(self) -> Iterator[str]:
        return iter(self.__dict__)

    def __len__(self) -> int:
        return len(self.__dict__)

    def __getitem__(self, key: str) -> Any:
        return reduce(lambda d, k: self.setdefault(k, HashedDataBlock()), key.split("."), self.__dict__)

    def __setitem__(self, key: str, value) -> NoReturn:
        *keys, last_key = key.split(".")
        reduce(lambda d, k: d.setdefault(k, HashedDataBlock()), keys, self.__dict__)[last_key] = value

    def __delitem__(self, key: str) -> NoReturn:
        *keys, last_key = key.split(".")
        del reduce(lambda d, k: d.setdefault(k, HashedDataBlock()), keys, self.__dict__)[last_key]

    def __getstate__(self) -> tuple[bytes, bytes]:
        return (data := dumps(self.__dict__)), getattr(hashlib, self.__block_hash__)(data).digest()

    def __setstate__(self, state: tuple[bytes, bytes]) -> NoReturn:
        data, hashed = state
        assert hashed == getattr(hashlib, self.__block_hash__)(data).digest(), "Data integrity compromised"
        self.__dict__.update(loads(data))
