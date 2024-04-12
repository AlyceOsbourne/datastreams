import rsa

from file_system import Signer

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


class CompoundSigner(Signer):
    def __init__(self, signers):
        self.signers = signers
        
    def sign(self, data: bytes) -> bytes:
        for signer in self.signers:
            data = signer.sign(data)
        return data

    def verify(self, data: bytes, signature: bytes) -> bool:
        for signer in reversed(self.signers):
            if not signer.verify(data, signature):
                return False
        return True