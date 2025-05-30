import json
import os
import sys
from dataclasses import dataclass
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA256, SM3

from PySide6.QtWidgets import (QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
                              QInputDialog, QMessageBox, QVBoxLayout, QWidget, QLineEdit,
                              QPushButton, QMenu, QToolTip)
from PySide6.QtGui import QAction, Qt, QCursor


DATA_FILE_PATH = "secret.dat"


@dataclass
class Row:
    id: int
    name: str
    address: str
    username: str
    password: str


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

        password, _ = QInputDialog.getText(self, "Input key", "Please input encryption key", QLineEdit.EchoMode.Password)

        self.latest_id: int = 0
        self.data: list[Row] = []
        self.cipher: Cipher

        if os.path.isdir(data_file_path):
            raise Exception(f"存在与data文件重名的目录 {data_file_path}")

        elif os.path.exists(data_file_path) and os.path.getsize(data_file_path) >= 88:
            self.data_file = open(data_file_path, "rb+")
            iv = self.data_file.read(16)
            self.cipher = Cipher(password, iv)

            uuid = self.data_file.read(36)
            uuid_cipher = self.data_file.read(36)

            if uuid_cipher != self.cipher.encrypt(uuid):
                QMessageBox.critical(self, "Error", "Password error")
                raise Exception("password error")
            
            self.data = json.load(self.data_file)
            self.latest_id = self.data[-1].id

        else:
            self.data_file = open(data_file_path, "wb+")

            iv = os.urandom(16)
            self.data_file.write(iv)
            self.cipher = Cipher(password, iv)

            uuid = str(uuid4()).encode()
            self.data_file.write(uuid)
            self.data_file.write(self.cipher.encrypt(uuid))
            self.data_file.write(b"[]")

        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        
        self.table_widget = QTableWidget()
        self.table_widget.setColumnCount(5)
        self.table_widget.setHorizontalHeaderLabels(["id", "name", "address", "username", "password"])

        self.flush_table()

        self.table_widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table_widget.customContextMenuRequested.connect(self.show_context_menu)
        self.table_widget.itemClicked.connect(self.copy_item)

        self.add_btn = QPushButton("➕ 添加条目")
        self.add_btn.clicked.connect(self.add_data_row)
        
        layout.addWidget(self.table_widget)
        layout.addWidget(self.add_btn)
        central_widget.setLayout(layout)
        
        self.setWindowTitle("Manbo口令管理工具")
        self.setGeometry(400, 400, 600, 400)
    
    def flush_table(self):
        for row in self.data:
            self.add_ui_row(row)

    def add_ui_row(self, row: Row):
        row_position = self.table_widget.rowCount()
        self.table_widget.insertRow(row_position)
        self.table_widget.setItem(row_position, 0, QTableWidgetItem(row.id))
        self.table_widget.setItem(row_position, 1, QTableWidgetItem(row.name))
        self.table_widget.setItem(row_position, 2, QTableWidgetItem(row.address))
        self.table_widget.setItem(row_position, 3, QTableWidgetItem(row.username))
        self.table_widget.setItem(row_position, 4, QTableWidgetItem(row.password))

    def add_data_row(self):
        name = QInputDialog.getText(self, "名称", "输入名称:")[0].strip()
        address = QInputDialog.getText(self, "地址", "输入地址:")[0].strip()
        username = QInputDialog.getText(self, "账号", "输入账号:")[0].strip()
        password = QInputDialog.getText(self, "密码", "输入密码:", QLineEdit.EchoMode.Password)[0].strip()
        password = self.cipher.encrypt(password.encode()).hex()
        self.latest_id += 1

        row = Row(self.latest_id ,name, address, username, password)        
        self.add_ui_row(row)

    def copy_item(self, qitem: QTableWidgetItem):
        column_number = qitem.column()
        if column_number == 4:
            data: str = qitem.data(Qt.ItemDataRole.UserRole)
            value = self.cipher.decrypt(bytes.fromhex(data)).decode()
        else:
            value = qitem.text()
        QApplication.clipboard().setText(value)
        QToolTip.showText(QCursor.pos(), "已复制: " + value)

    def show_context_menu(self, pos):
        row_number = self.table_widget.rowAt(pos)
        if not row_number: return
        
        menu = QMenu()
        delete_action = QAction("删除条目", self)
        delete_action.triggered.connect(lambda: self.delete_row(row_number))
        menu.addAction(delete_action)
        menu.exec_(self.table_widget.mapToGlobal(pos))

    def delete_row(self, row_number: int):
        self.data.pop(row_number)
        self.table_widget.removeRow(row_number)

    def save(self):
        self.data_file.seek(88)
        data_stream = json.dumps(self.data).encode()
        self.data_file.write(data_stream)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = ManboPasswordManager(DATA_FILE_PATH)
    window.show()
    sys.exit(app.exec())
