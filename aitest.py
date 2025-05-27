import json
import os
import sys
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA256, SM3

from PySide6.QtWidgets import (QApplication, QMainWindow, QListWidget, QListWidgetItem,
                              QInputDialog, QMessageBox, QVBoxLayout, QWidget, QLineEdit,
                              QPushButton, QMenu)
from PySide6.QtGui import QAction, Qt, QAccessible


DATA_FILE_PATH = "secret.dat"


class Cipher:
    def __init__(self, password: str, iv: bytes, algorithm=algorithms.AES256, mode=modes.CTR, _hash=SHA256):
        assert algorithm.block_size == 128

        digest = Hash(_hash())
        digest.update(password.encode())

        key = digest.finalize()
        self.cipher = _Cipher(algorithm(key), mode(iv))
    
    def encrypt(self, plaintext: bytes) -> bytes:
        encryptor = self.cipher.encryptor()
        encryptor.update(plaintext)
        return encryptor.finalize()

    def decrypt(self, ciphertext: bytes) -> bytes:
        decryptor = self.cipher.decryptor()
        decryptor.update(ciphertext)
        return decryptor.finalize()


class ManboPasswordManager(QMainWindow):
    """
    byte # iv(16) + uuid_plaintext(36) + uuid_cipher(36)

    code:
        1: error password
    """
    def __init__(self, data_file_path: str):
        super().__init__()

        password, ok = QInputDialog.getText(self, "Input key", "Please input encryption key", QLineEdit.EchoMode.Password)

        data_file = None
        iv = None

        if os.path.isdir(data_file_path):
            raise Exception(f"存在与data文件重名的目录 {data_file_path}")
        
        elif os.path.exists(data_file_path):
            data_file = open(data_file_path, "rb+")
            iv = data_file.read(16)
            self.cipher = Cipher(password, iv)

            uuid = data_file.read(36)
            uuid_cipher = data_file.read(36)

            if uuid_cipher != self.cipher.encrypt(uuid):
                QMessageBox.critical(self, "Error", "Password error")
                raise Exception("password error")

        else:
            data_file = open(data_file_path, "rb+")

            iv = os.urandom(16)
            data_file.write(iv)
            self.cipher = Cipher(password, iv)

            uuid = str(uuid4()).encode()
            data_file.write(uuid)
            data_file.write(self.cipher.encrypt(uuid))

        self.init_ui()
        self.load_data()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        
        self.list_widget = QListWidget()
        self.list_widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.list_widget.customContextMenuRequested.connect(self.show_context_menu)
        self.list_widget.itemClicked.connect(self.copy_password)
        
        self.add_btn = QPushButton("➕ 添加条目")
        self.add_btn.clicked.connect(self.add_entry)
        
        layout.addWidget(self.list_widget)
        layout.addWidget(self.add_btn)
        central_widget.setLayout(layout)
        
        self.setWindowTitle("Manbo口令管理工具")
        self.setGeometry(400, 400, 600, 400)

    def add_entry(self):
        server, ok1 = QInputDialog.getText(self, "服务名称", "输入服务名称:")
        username, ok2 = QInputDialog.getText(self, "用户名", "输入用户名:")
        password, ok3 = QInputDialog.getText(self, "密码", "输入密码:", QLineEdit.EchoMode.Password)
        
        if all([ok1, ok2, ok3]):
            self.passwords.append({
                "server": server,
                "username": username,
                "password": password
            })
            self.update_list()
            self.save_data()

    def update_list(self):
        """更新列表显示"""
        self.list_widget.clear()
        for item in self.passwords:
            entry = QListWidgetItem(f"{item['service']} - {item['username']}")
            entry.setData(QAccessible.Role.UserRole, item)  # type: ignore
            self.list_widget.addItem(entry)

    def copy_password(self, item):
        """复制密码到剪贴板（网页1核心功能）"""
        data = item.data(QAccessible.Role.UserRole)
        QApplication.clipboard().setText(data['password'])
        QMessageBox.information(self, "操作成功", "密码已复制到剪贴板")

    def save_data(self):
        """加密存储数据（网页5本地加密设计）"""
        plain_data = json.dumps(self.passwords).encode()
        encrypted = self.cipher.encrypt(plain_data)
        with open(self.data_file, 'wb') as f:
            f.write(encrypted)

    def load_data(self):
        """解密加载数据"""
        try:
            with open(self.data_file, 'rb') as f:
                decrypted = self.crypto.decrypt(f.read())
                self.passwords = json.loads(decrypted)
                self.update_list()
        except (FileNotFoundError, json.JSONDecodeError):
            self.passwords = []

    def show_context_menu(self, pos):
        """右键菜单（网页1删除功能）"""
        item = self.list_widget.itemAt(pos)
        if not item: return
        
        menu = QMenu()
        delete_action = QAction("删除条目", self)
        delete_action.triggered.connect(lambda: self.delete_item(item))
        menu.addAction(delete_action)
        menu.exec_(self.list_widget.mapToGlobal(pos))

    def delete_item(self, item):
        row = self.list_widget.row(item)
        self.list_widget.takeItem(row)
        del self.passwords[row]
        self.save_data()

    def closeEvent(self, event):
        """内存安全擦除（网页6安全实践）"""
        self.crypto.key = b'\x00'*32
        event.accept()

def validate_key(key):
    """密钥有效性验证（网页2/6安全校验）"""
    try:
        cipher = AES256CTR(key)
        decrypted = cipher.decrypt(TEST_CIPHERTEXT)
        return decrypted == TEST_PLAINTEXT
    except Exception:
        return False


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = ManboPasswordManager(DATA_FILE_PATH)
    window.show()
    sys.exit(app.exec())
