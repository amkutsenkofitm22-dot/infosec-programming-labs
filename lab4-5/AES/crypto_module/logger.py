import logging
import os
from datetime import datetime

class CryptoLogger:
    _initialized = False 

    def __init__(self, log_file="logs/crypto.log"):
        if CryptoLogger._initialized:
            self.logger = logging.getLogger("CryptoApp")
            return

        os.makedirs("logs", exist_ok=True)

        self.logger = logging.getLogger("CryptoApp")
        self.logger.setLevel(logging.INFO)

        self.logger.handlers.clear()

        formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s')
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        CryptoLogger._initialized = True

    def log_success(self, msg: str):
        self.logger.info(f"SUCCESS | {msg}")

    def log_error(self, msg: str):
        self.logger.error(f"ERROR   | {msg}")

    def log_warning(self, msg: str):
        self.logger.warning(f"WARNING | {msg}")