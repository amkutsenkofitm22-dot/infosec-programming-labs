import socket
import ssl
import hashlib
import logging

logging.basicConfig(filename='client.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations("cert.pem")   
context.check_hostname = False            

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssock = context.wrap_socket(sock, server_hostname="localhost")

try:
    ssock.connect(('127.0.0.1', 8443))
    logging.info("TLS-з'єднання встановлено")

    ssock.send("admin:admin123".encode('utf-8'))
    auth_response = ssock.recv(1024).decode('utf-8')
    print(f"Відповідь на аутентифікацію: {auth_response}")

    if auth_response != "OK":
        raise Exception("Аутентифікація провалилась")

    message = "Hello World!"
    message_hash = sha256_hash(message)
    payload = f"{message}|{message_hash}"
    ssock.send(payload.encode('utf-8'))
    logging.info(f"Відправлено: {payload}")

    print("Повідомлення успішно відправлено!")
    print(f"   Текст: {message}")
    print(f"   SHA-256: {message_hash}")

    print("\n=== Інформація про TLS-сесію ===")
    print(f"TLS версія   : {ssock.version()}")
    print(f"Шифр         : {ssock.cipher()}")
    cert = ssock.getpeercert()
    print(f"Сертифікат   : {cert.get('subjectAltName', 'немає')}")
    print(f"Дійсний до   : {cert['notAfter']}")

except Exception as e:
    print(f"Помилка: {e}")
    logging.error(f"Помилка: {e}")
finally:
    ssock.close()