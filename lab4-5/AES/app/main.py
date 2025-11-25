import os
import json
import time
from crypto_module.key_manager import KeyManager
from crypto_module.aes_encryptor import AESEncryptor

ENCRYPTED_DIR = "encrypted_files"
DECRYPTED_DIR = "decrypted_files"


def save_json(data: dict, default_name: str):
    os.makedirs(ENCRYPTED_DIR, exist_ok=True)
    filename = input(f"Шлях для збереження (Enter = {default_name}): ").strip()
    if not filename:
        filename = os.path.join(ENCRYPTED_DIR, default_name)
    else:
        filename = os.path.join(ENCRYPTED_DIR, filename)
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Зашифрований файл збережено → {filename}")
    return filename


def save_decrypted(data: bytes, original_name: str):
    os.makedirs(DECRYPTED_DIR, exist_ok=True)
    default_name = f"decrypted_{original_name}_{int(time.time())}"
    filename = input(f"Шлях для розшифрованого файлу (Enter = {default_name}): ").strip()
    if not filename:
        filename = os.path.join(DECRYPTED_DIR, default_name)
    
    with open(filename, 'wb') as f:
        f.write(data)
    print(f"Розшифрований файл збережено → {filename}")
    return filename


def load_encrypted_file():
    path = input(f"Шлях до зашифрованого файлу (з папки {ENCRYPTED_DIR}): ").strip()
    if not path:
        print("Помилка: шлях не вказано!")
        return None, None
    if not os.path.isabs(path):
        path = os.path.join(ENCRYPTED_DIR, path)
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"Завантажено зашифрований файл → {path}")
        return data, path
    except Exception as e:
        print(f"Не вдалося відкрити файл: {e}")
        return None, None


def encrypt_file():
    print("\nРежим: ШИФРУВАННЯ")
    password = input("Введіть пароль: ").strip()
    if not password:
        print("Пароль не може бути порожнім!")
        return
    
    mode = input("Режим (GCM / CBC) [за замовчуванням GCM]: ").strip().upper() or "GCM"
    
    input_path = input("Шлях до файлу для шифрування: ").strip()
    if not os.path.exists(input_path):
        print("Файл не знайдено!")
        return

    km = KeyManager(password)
    key = km.derive_key()
    encryptor = AESEncryptor(key, mode)

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    encrypted_data = encryptor.encrypt(plaintext)
    encrypted_data['salt'] = km.get_salt_b64()
    encrypted_data['original_name'] = os.path.basename(input_path)
    encrypted_data['mode'] = mode

    timestamp = int(time.time())
    default_name = f"enc_{timestamp}_{os.path.basename(input_path)}.json"
    save_json(encrypted_data, default_name)


def decrypt_file():
    print("\nРежим: ДЕШИФРУВАННЯ")
    password = input("Введіть пароль: ").strip()
    
    data, filepath = load_encrypted_file()
    if not data:
        return

    try:
        salt = KeyManager.load_salt_from_b64(data['salt'])
        km = KeyManager(password, salt)
        key = km.derive_key()
        mode = data.get('mode', 'GCM')

        encryptor = AESEncryptor(key, mode)
        decrypted = encryptor.decrypt(data)

        original_name = data.get('original_name', 'file')
        save_decrypted(decrypted, original_name)

    except Exception as e:
        print(f"ПОМИЛКА ДЕШИФРУВАННЯ (неправильний пароль або підміна даних): {e}")


def main():
    os.makedirs("logs", exist_ok=True)
    print("=" * 60)
    print("   AES КРИПТОГРАФІЧНИЙ МОДУЛЬ (GCM + CBC)")
    print("   Зашифровані файли → encrypted_files/")
    print("   Розшифровані файли → decrypted_files/")
    print("=" * 60)

    while True:
        print("\nОберіть дію:")
        print("1 — Зашифрувати файл")
        print("2 — Розшифрувати файл")
        print("0 — Вихід")
        choice = input("→ ").strip()

        if choice == "1":
            encrypt_file()
        elif choice == "2":
            decrypt_file()
        elif choice in ("0", ""):
            print("До побачення!")
            break
        else:
            print("Невірний вибір!")


if __name__ == "__main__":
    main()