import time
import os
from crypto_module.key_manager import KeyManager
from crypto_module.aes_encryptor import AESEncryptor

sizes = [1*1024*1024, 10*1024*1024, 100*1024*1024]
modes = ['GCM', 'CBC']
results = []

km = KeyManager("strongpassword123")
key = km.derive_key()

for mode in modes:
    for size in sizes:
        data = os.urandom(size)
        enc = AESEncryptor(key, mode)

        start = time.time()
        enc.encrypt(data)
        encrypt_time = time.time() - start

        encrypted = enc.encrypt(data)
        start = time.time()
        enc.decrypt(encrypted)
        decrypt_time = time.time() - start

        results.append({
            'mode': mode,
            'size_mb': size // (1024*1024),
            'encrypt_ms': round(encrypt_time * 1000, 2),
            'decrypt_ms': round(decrypt_time * 1000, 2),
            'total_ms': round((encrypt_time + decrypt_time) * 1000, 2)
        })

# Вивід таблиці
print("| Режим | Розмір | Шифрування (мс) | Дешифрування (мс) |")
print("|-------|--------|-----------------|-------------------|")
for r in results:
    print(f"| {r['mode']:5} | {r['size_mb']:6} | {r['encrypt_ms']:15} | {r['decrypt_ms']:17} |")