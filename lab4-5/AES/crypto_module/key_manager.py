import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class KeyManager:
    def __init__(self, password: str, salt: bytes = None):
        self.password = password.encode()
        self.salt = salt or os.urandom(16)

    def derive_key(self, key_length: int = 32) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=self.salt,
            iterations=200_000,
        )
        key = kdf.derive(self.password)
        return key

    def get_salt_b64(self) -> str:
        return base64.b64encode(self.salt).decode()

    @staticmethod
    def load_salt_from_b64(salt_b64: str) -> bytes:
        return base64.b64decode(salt_b64)