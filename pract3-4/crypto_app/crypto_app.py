import os
import time
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidTag

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return kdf.derive(password.encode())


def aes_encrypt(message: bytes, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)
    aes = AESGCM(key)

    start = time.time()
    ciphertext = aes.encrypt(nonce, message, None)
    end = time.time()

    return salt, nonce, ciphertext, end - start


def aes_decrypt(salt, nonce, ciphertext, password: str):
    key = derive_key(password, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key, private_key.public_key()


def rsa_encrypt(public_key, data: bytes):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(private_key, data: bytes):
    return private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def symmetric_encrypt():
    print("\n[ AES — Шифрування ]")
    message = input("Введіть повідомлення: ").encode()
    password = input("Введіть пароль: ")

    salt, nonce, ciphertext, enc_time = aes_encrypt(message, password)

    print("\nАлгоритм: AES-GCM (256 біт)")
    print("Час шифрування:", round(enc_time, 6), "сек")

    print("\n--- Дані для розшифрування ---")
    print("Salt:", base64.b64encode(salt).decode())
    print("Nonce:", base64.b64encode(nonce).decode())
    print("Ciphertext:", base64.b64encode(ciphertext).decode())


def symmetric_decrypt():
    print("\n[ AES — Розшифрування ]")
    password = input("Введіть пароль: ")

    salt = base64.b64decode(input("Salt (Base64): "))
    nonce = base64.b64decode(input("Nonce (Base64): "))
    ciphertext = base64.b64decode(input("Ciphertext (Base64): "))

    try:
        decrypted = aes_decrypt(salt, nonce, ciphertext, password)
        print("Розшифроване повідомлення:", decrypted.decode())
    except InvalidTag:
        print("Помилка: неправильний пароль або пошкоджені дані!")


def asymmetric_encrypt():
    print("\n[ RSA — Шифрування ]")
    message = input("Введіть повідомлення: ").encode()

    private_key, public_key = generate_rsa_keys()

    start = time.time()
    encrypted = rsa_encrypt(public_key, message)
    end = time.time()

    print("\nАлгоритм: RSA (2048 біт)")
    print("Час шифрування:", round(end - start, 6), "сек")
    print("Ciphertext:", base64.b64encode(encrypted).decode())

    return private_key


def asymmetric_decrypt(private_key):
    print("\n[ RSA — Розшифрування ]")
    encrypted = base64.b64decode(input("Ciphertext (Base64): "))
    decrypted = rsa_decrypt(private_key, encrypted)
    print("Розшифроване повідомлення:", decrypted.decode())


def hybrid_encrypt():
    print("\n[ Гібридне — Шифрування ]")
    message = input("Введіть повідомлення: ").encode()
    password = input("Введіть пароль для AES: ")

    salt, nonce, ciphertext, enc_time = aes_encrypt(message, password)
    aes_key = derive_key(password, salt)

    private_key, public_key = generate_rsa_keys()
    encrypted_key = rsa_encrypt(public_key, aes_key)

    print("\nАлгоритми: AES-GCM + RSA")
    print("Час AES шифрування:", round(enc_time, 6), "сек")

    print("\n--- Дані для розшифрування ---")
    print("Encrypted AES key:", base64.b64encode(encrypted_key).decode())
    print("Salt:", base64.b64encode(salt).decode())
    print("Nonce:", base64.b64encode(nonce).decode())
    print("Ciphertext:", base64.b64encode(ciphertext).decode())

    return private_key


def hybrid_decrypt(private_key):
    print("\n[ Гібридне — Розшифрування ]")
    password = input("Введіть пароль для AES: ")

    encrypted_key = base64.b64decode(input("Encrypted AES key (Base64): "))
    salt = base64.b64decode(input("Salt (Base64): "))
    nonce = base64.b64decode(input("Nonce (Base64): "))
    ciphertext = base64.b64decode(input("Ciphertext (Base64): "))

    try:
        aes_key = rsa_decrypt(private_key, encrypted_key)
        aes = AESGCM(aes_key)
        decrypted = aes.decrypt(nonce, ciphertext, None)
        print("Розшифроване повідомлення:", decrypted.decode())
    except InvalidTag:
        print("Помилка дешифрування або автентифікації!")

def main_menu():
    rsa_private_key = None

    while True:
        print("\n====== КРИПТОГРАФІЧНИЙ МОДУЛЬ ======")
        print("1 - AES: Шифрувати")
        print("2 - AES: Розшифрувати")
        print("3 - RSA: Шифрувати")
        print("4 - RSA: Розшифрувати")
        print("5 - Гібридне: Шифрувати")
        print("6 - Гібридне: Розшифрувати")
        print("0 - Вихід")

        choice = input("Оберіть дію: ")

        if choice == "1":
            symmetric_encrypt()
        elif choice == "2":
            symmetric_decrypt()
        elif choice == "3":
            rsa_private_key = asymmetric_encrypt()
        elif choice == "4":
            if rsa_private_key:
                asymmetric_decrypt(rsa_private_key)
            else:
                print("Спочатку виконайте RSA-шифрування!")
        elif choice == "5":
            rsa_private_key = hybrid_encrypt()
        elif choice == "6":
            if rsa_private_key:
                hybrid_decrypt(rsa_private_key)
            else:
                print("Спочатку виконайте гібридне шифрування!")
        elif choice == "0":
            print("Завершення роботи.")
            break
        else:
            print("Невірний вибір!")


if __name__ == "__main__":
    main_menu()
