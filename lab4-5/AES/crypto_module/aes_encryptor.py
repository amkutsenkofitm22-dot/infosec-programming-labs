import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.exceptions import InvalidTag
from .logger import CryptoLogger

class AESEncryptor:
    SUPPORTED_MODES = ['CBC', 'GCM']

    def __init__(self, key: bytes, mode: str = 'GCM'):
        if mode not in self.SUPPORTED_MODES:
            raise ValueError(f"Підтримуются тільки: {self.SUPPORTED_MODES}")
        self.key = key
        self.mode = mode
        self.logger = CryptoLogger()

    def encrypt(self, plaintext: bytes) -> dict:
        if self.mode == 'GCM':
            return self._encrypt_gcm(plaintext)
        elif self.mode == 'CBC':
            return self._encrypt_cbc(plaintext)

    def decrypt(self, data: dict) -> bytes:
        if data['mode'] == 'GCM':
            return self._decrypt_gcm(data)
        elif data['mode'] == 'CBC':
            return self._decrypt_cbc(data)

    def _encrypt_gcm(self, plaintext: bytes) -> dict:
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(self.key), modes.GCM(iv))
        encryptor = encryptor.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag

        result = {
            'mode': 'GCM',
            'iv': base64.b64encode(iv).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode()
        }
        self.logger.log_success("GCM шифрування успішне")
        return result

    def _decrypt_gcm(self, data: dict) -> bytes:
        try:
            iv = base64.b64decode(data['iv'])
            ciphertext = base64.b64decode(data['ciphertext'])
            tag = base64.b64decode(data['tag'])

            decryptor = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag))
            decryptor = decryptor.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            self.logger.log_success("GCM дешифрування успішне")
            return plaintext
        except InvalidTag:
            self.logger.log_error("GCM: тег аутентифікації не співпадає – дані підмінено!")
            raise

    def _encrypt_cbc(self, plaintext: bytes) -> dict:
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        h = hmac.HMAC(self.key, hashes.SHA256())
        h.update(ciphertext)
        mac = h.finalize()

        result = {
            'mode': 'CBC',
            'iv': base64.b64encode(iv).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'mac': base64.b64encode(mac).decode()
        }
        self.logger.log_success("CBC шифрування успішне (з HMAC)")
        return result

    def _decrypt_cbc(self, data: dict) -> bytes:
        try:
            iv = base64.b64decode(data['iv'])
            ciphertext = base64.b64decode(data['ciphertext'])
            mac_received = base64.b64decode(data['mac'])

            h = hmac.HMAC(self.key, hashes.SHA256())
            h.update(ciphertext)
            h.verify(mac_received)

            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            self.logger.log_success("CBC дешифрування успішне")
            return plaintext
        except Exception as e:
            self.logger.log_error(f"CBC помилка (можливо підміна): {str(e)}")
            raise