import socket
import ssl
import logging

logging.basicConfig(filename='server.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

def authenticate(data: bytes) -> bool:
    try:
        credentials = data.decode('utf-8').strip()
        login, password = credentials.split(':')
        return login == "admin" and password == "admin123"
    except:
        return False

# TLS контекст
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 8443))
    sock.listen(5)
    print("Сервер запущено на 127.0.0.1:8443 (TLS)")

    with context.wrap_socket(sock, server_side=True) as ssock:
        while True:
            try:
                conn, addr = ssock.accept()
                logging.info(f"Нове з'єднання від {addr}")

                data = conn.recv(1024)
                if authenticate(data):
                    conn.send(b'OK')
                    logging.info(f"Успішна аутентифікація від {addr}")
                    payload = conn.recv(1024).decode('utf-8', errors='ignore')
                    logging.info(f"Отримано дані: {payload}")
                else:
                    conn.send(b'FAIL')
                    logging.info(f"Невдала аутентифікація від {addr}")
                conn.close()
            except Exception as e:
                logging.error(f"Помилка обробки з'єднання: {e}")