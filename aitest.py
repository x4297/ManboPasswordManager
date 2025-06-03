import json
import os
import sys
import time
from dataclasses import dataclass, asdict, fields
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA256, SM3, SHA1
from cryptography.hazmat.primitives.twofactor.totp import TOTP

from PySide6.QtCore import QPoint
from PySide6.QtWidgets import (QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
                              QInputDialog, QMessageBox, QVBoxLayout, QWidget, QLineEdit,
                              QPushButton, QMenu, QToolTip)
from PySide6.QtGui import QAction, QCloseEvent, Qt, QCursor


DATA_FILE_PATH = "secret.dat"


@dataclass
class Row:
    id: int
    name: str
    type: str
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
        return encryptor.update(plaintext) + encryptor.finalize()

    def decrypt(self, ciphertext: bytes) -> bytes:
        decryptor = self.cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


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
        self.data_file_path: str = data_file_path

        if os.path.isdir(data_file_path):
            raise Exception(f"存在与data文件重名的目录 {data_file_path}")

        elif os.path.exists(data_file_path) and os.path.getsize(data_file_path) >= 88:
            with open(data_file_path, "rb+") as f:
                iv = f.read(16)
                self.cipher = Cipher(password, iv)

                uuid = f.read(36)
                uuid_cipher = f.read(36)

                if uuid_cipher != self.cipher.encrypt(uuid):
                    QMessageBox.critical(self, "Error", "Password error")
                    raise Exception("password error")

                self.data = [Row(**row) for row in json.load(f)]
                self.latest_id = 0 if len(self.data) == 0 else self.data[-1].id + 1

        else:
            with open(data_file_path, "wb+") as f:
                iv = os.urandom(16)
                f.write(iv)
                self.cipher = Cipher(password, iv)

                uuid = str(uuid4()).encode()
                f.write(uuid)
                f.write(self.cipher.encrypt(uuid))
                f.write(b"[]")

        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        
        row_fields = fields(Row)
        self.table_widget = QTableWidget()
        self.table_widget.setColumnCount(len(row_fields))
        self.table_widget.setHorizontalHeaderLabels([f.name for f in row_fields])

        self.flush_table()

        # self.table_widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        # self.table_widget.customContextMenuRequested.connect(self.show_context_menu)

        self.table_widget.itemClicked.connect(self.copy_item)

        self.add_button = QPushButton("添加条目")
        self.add_button.clicked.connect(self.add_data_row)

        self.save_button = QPushButton("保存")
        self.save_button.clicked.connect(self.save)
        
        layout.addWidget(self.table_widget)
        layout.addWidget(self.add_button)
        layout.addWidget(self.save_button)
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
        self.table_widget.setItem(row_position, 2, QTableWidgetItem(row.type))
        self.table_widget.setItem(row_position, 3, QTableWidgetItem(row.address))
        self.table_widget.setItem(row_position, 4, QTableWidgetItem(row.username))
        self.table_widget.setItem(row_position, 5, QTableWidgetItem(row.password))

    def add_data_row(self):
        name = QInputDialog.getText(self, "名称", "输入名称:")[0].strip()
        type = QInputDialog.getItem(self, "类型", "输入类型(password or totp):", ["password", "totp"], 0, False)[0].strip()
        address = QInputDialog.getText(self, "地址", "输入地址:")[0].strip()
        username = QInputDialog.getText(self, "账号", "输入账号:")[0].strip()
        password = QInputDialog.getText(self, "密码", "输入密码:", QLineEdit.EchoMode.Password)[0].strip()

        if type == "totp" and len(password) < 32:
            QMessageBox.critical(self, "错误", "totp密钥长度不能小于128bit")
            return

        password = self.cipher.encrypt(password.encode()).hex()
        self.latest_id += 1

        row = Row(self.latest_id, name, type, address, username, password)
        self.data.append(row)
        self.add_ui_row(row)

    def copy_item(self, qitem: QTableWidgetItem):
        column_number = qitem.column()
        if column_number == 5:
            row_number = qitem.row()
            data = qitem.text()
            value = self.cipher.decrypt(bytes.fromhex(data)).decode()
            if self.data[row_number].type == "totp":
                totp = TOTP(value.encode(), 6, SHA1(), 30)
                value = totp.generate(time.time()).decode()
            QToolTip.showText(QCursor.pos(), "已复制: ******")
        else:
            value = qitem.text()
            QToolTip.showText(QCursor.pos(), "已复制: " + value)
        QApplication.clipboard().setText(value)

    # def show_context_menu(self, pos: QPoint):
    #     row_number = self.table_widget.rowAt(pos.y())
    #     if not row_number: return
        
    #     menu = QMenu()
    #     delete_action = QAction("删除条目", self)
    #     delete_action.triggered.connect(lambda: self.delete_row(row_number))
    #     menu.addAction(delete_action)
    #     menu.exec_(self.table_widget.mapToGlobal(pos))

    def delete_row(self, row_number: int):
        self.data.pop(row_number)
        self.table_widget.removeRow(row_number)

    def save(self):
        with open(self.data_file_path, "rb+") as f:
            f.seek(88)
            data_stream = json.dumps([asdict(row) for row in self.data]).encode()
            f.write(data_stream)

    def closeEvent(self, event: QCloseEvent) -> None:
        self.save()
        return super().closeEvent(event)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = ManboPasswordManager(DATA_FILE_PATH)
    window.show()
    sys.exit(app.exec())
