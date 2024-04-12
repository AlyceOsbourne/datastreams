import rsa
import abc
import hashlib
import platform
import uuid
import hmac
import ecdsa
import marshal

class Signer(abc.ABC):
    @abc.abstractmethod
    def sign(self, data: bytes) -> bytes:
        pass

    @abc.abstractmethod
    def verify(self, data: bytes, signature: bytes) -> bool:
        pass

class HashSigner(Signer):
    def __init__(self, hash_algorithm: str):
        self.hash_algorithm = hash_algorithm

    def sign(self, data: bytes) -> bytes:
        return hashlib.new(self.hash_algorithm, data).digest()

    def verify(self, data: bytes, signature: bytes) -> bool:
        return signature == self.sign(data)

    @classmethod
    def new(cls, hash_algorithm: str):
        return cls(hash_algorithm)

class RSASigner(Signer):
    def __init__(self, public_key: rsa.PublicKey, private_key: rsa.PrivateKey):
        self.public_key = public_key
        self.private_key = private_key

    def sign(self, data: bytes) -> bytes:
        return rsa.sign(data, self.private_key, 'SHA-256')

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            rsa.verify(data, signature, self.public_key)
        except rsa.VerificationError:
            return False
        return True

    @classmethod
    def new(cls, bits: int = 2048):
        return cls(*rsa.newkeys(bits))

class FingerprintSigner(Signer):
    def __init__(self, fingerprint: str):
        self.fingerprint = fingerprint

    def sign(self, data: bytes) -> bytes:
        return hashlib.sha256(data + self.fingerprint.encode()).digest()

    def verify(self, data: bytes, signature: bytes) -> bool:
        return signature == self.sign(data)

    @classmethod
    def new(cls):
        system_info = {
                'processor': platform.processor(),
                'platform' : platform.platform(),
                'system'   : platform.system(),
                'machine'  : platform.machine(),
                'node'     : platform.node()
        }

        mac_address = uuid.UUID(int = uuid.getnode()).hex[-12:]
        system_info['mac'] = mac_address

        unique_string = "_".join(f"{key}:{value}" for key, value in system_info.items())
        hash_object = hashlib.sha256(unique_string.encode())
        system_hash = hash_object.hexdigest()
        return cls(system_hash)

class HMACSigner(Signer):
    def __init__(self, key: bytes):
        self.key = key

    def sign(self, data: bytes) -> bytes:
        return hmac.new(self.key, data, hashlib.sha256).digest()

    def verify(self, data: bytes, signature: bytes) -> bool:
        return signature == self.sign(data)

    @classmethod
    def new(cls):
        return cls(uuid.uuid4().bytes)

class ECDSASigner(Signer):
    def __init__(self, private_key: ecdsa.SigningKey, public_key: ecdsa.VerifyingKey):
        self.private_key = private_key
        self.public_key = public_key

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        return self.public_key.verify(signature, data)

    @classmethod
    def new(cls):
        private_key = ecdsa.SigningKey.generate()
        public_key = private_key.get_verifying_key()
        return cls(private_key, public_key)

class CompoundSigner(Signer):
    def __init__(self, *signers):
        self.signers = signers

    def sign(self, data: bytes) -> bytes:
        return marshal.dumps([signer.sign(data) for signer in self.signers])
    
    def verify(self, data: bytes, signatures: bytes) -> bool:
        return all(signer.verify(data, signature) for signer, signature in zip(self.signers, marshal.loads(signatures)))