# user.py v1.4
# https://github.com/xhdndmm/meow-chat

import sys
import socket
import json
import os
import sqlite3
import hmac
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QTextEdit, QLabel, QMessageBox
)
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QAction

LOCAL_DB = "local_chat.db"

# --- 安全配置 ---
ENCRYPTION_KEY = b'meow-chat-fixed-32-byte-key-v1.4'
aesgcm = AESGCM(ENCRYPTION_KEY)
SHARED_SECRET = "meow-chat-secret-v1"

def encrypt_payload(data_dict):
    data_bytes = json.dumps(data_dict).encode('utf-8')
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data_bytes, None)
    return nonce + ciphertext

def decrypt_payload(raw_bytes):
    nonce = raw_bytes[:12]
    ciphertext = raw_bytes[12:]
    data_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(data_bytes.decode('utf-8'))

def send_secure_msg(sock, data_dict):
    encrypted = encrypt_payload(data_dict)
    length = len(encrypted).to_bytes(4, byteorder='big')
    sock.sendall(length + encrypted)

def read_secure_msg(sock):
    raw_len = sock.recv(4)
    if not raw_len: return None
    msg_len = int.from_bytes(raw_len, byteorder='big')
    chunks = []
    bytes_recd = 0
    while bytes_recd < msg_len:
        chunk = sock.recv(min(msg_len - bytes_recd, 2048))
        if not chunk: break
        chunks.append(chunk)
        bytes_recd += len(chunk)
    return decrypt_payload(b''.join(chunks))

# ---------------- SQLite 本地存储 ----------------
def init_local_db():
    conn = sqlite3.connect(LOCAL_DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS local_chat (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            message TEXT,
            ip TEXT,
            time TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_message_local(username, message, ip, time):
    conn = sqlite3.connect(LOCAL_DB)
    cur = conn.cursor()
    cur.execute("INSERT INTO local_chat (username, message, ip, time) VALUES (?, ?, ?, ?)", (username, message, ip, time))
    conn.commit()
    conn.close()

def get_last_message_time():
    conn = sqlite3.connect(LOCAL_DB)
    cur = conn.cursor()
    cur.execute("SELECT time FROM local_chat ORDER BY time DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row[0] if row else "1970-01-01 00:00:00"

# --------------- 服务器校验 ----------------
def hmac_sha256(key, msg):
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()

def client_handshake(sock):
    try:
        # 1. 发送 HELLO
        send_secure_msg(sock, {"type": "hello"})
        # 2. 接收 challenge
        data = read_secure_msg(sock)
        if not data or data.get("type") != "challenge": return False
        # 3. 回应 HMAC
        digest = hmac_sha256(SHARED_SECRET, data["challenge"])
        send_secure_msg(sock, {"type": "response", "hmac": digest})
        return True
    except: return False

class ChatReceiver(QThread):
    new_message = pyqtSignal(str)
    update_online_users = pyqtSignal(int)
    notify_message = pyqtSignal(str)

    def __init__(self, client_socket):
        super().__init__()
        self.client_socket = client_socket
        self.running = True

    def run(self):
        while self.running:
            try:
                data = read_secure_msg(self.client_socket)
                if not data: break
                if data.get("type") == "history":
                    for msg in data["data"]:
                        text = f"{msg['username']} ({msg['time']}): {msg['message']}"
                        save_message_local(msg["username"], msg["message"], msg.get("ip", ""), msg["time"])
                        self.new_message.emit(text)
                elif data.get("type") == "online_users":
                    self.update_online_users.emit(data["count"])
                elif data.get("type") == "login":
                    if data.get("message"): self.notify_message.emit(data["message"])
                else:
                    text = f"{data['username']} ({data.get('time', 'unknown')}): {data['message']}"
                    save_message_local(data["username"], data["message"], data.get("ip", ""), data.get("time", ""))
                    self.new_message.emit(text)
            except: break

    def stop(self):
        self.running = False
        self.quit()
        self.wait()

# ---------------- 主界面 ----------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowOpacity(0.95)
        self.client_socket = None
        self.receiver_thread = None
        init_local_db()
        self.init_ui()

        toolbar = self.addToolBar("功能栏")
        toolbar.setMovable(False)
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about)
        toolbar.addAction(about_action)
        self.online_users_label = QLabel("在线人数: 0")
        toolbar.addWidget(self.online_users_label)

    def init_ui(self):
        self.setWindowTitle("meow-chat-user-v1.4")
        central = QWidget()
        self.setCentralWidget(central)
        v_layout = QVBoxLayout()

        # 连接区
        h_conn = QHBoxLayout()
        h_conn.addWidget(QLabel("服务器地址:"))
        self.server_ip_edit = QLineEdit()
        h_conn.addWidget(self.server_ip_edit)

        h_conn.addWidget(QLabel("用户名:"))
        self.username_edit = QLineEdit()
        h_conn.addWidget(self.username_edit)

        h_conn.addWidget(QLabel("密码:"))
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        h_conn.addWidget(self.password_edit)

        self.login_btn = QPushButton("登录")
        self.login_btn.clicked.connect(self.login_to_server)
        h_conn.addWidget(self.login_btn)

        self.register_btn = QPushButton("注册")
        self.register_btn.clicked.connect(self.register_account)
        h_conn.addWidget(self.register_btn)
        v_layout.addLayout(h_conn)

        # 聊天区
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        v_layout.addWidget(self.chat_area)

        # 控制按钮
        h_ctrl = QHBoxLayout()
        self.sync_btn = QPushButton("同步聊天记录")
        self.sync_btn.clicked.connect(self.sync_history)
        h_ctrl.addWidget(self.sync_btn)

        self.disconnect_btn = QPushButton("断开连接")
        self.disconnect_btn.clicked.connect(self.disconnect_from_server)
        h_ctrl.addWidget(self.disconnect_btn)
        v_layout.addLayout(h_ctrl)

        # 消息输入
        h_msg = QHBoxLayout()
        self.message_edit = QLineEdit()
        # 按 Enter (Return) 直接发送消息
        self.message_edit.returnPressed.connect(self.send_message)
        h_msg.addWidget(self.message_edit)
        self.send_btn = QPushButton("发送")
        self.send_btn.clicked.connect(self.send_message)
        h_msg.addWidget(self.send_btn)
        v_layout.addLayout(h_msg)

        central.setLayout(v_layout)

    def register_account(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.server_ip_edit.text(), 12345))
            if not client_handshake(sock):
                QMessageBox.warning(self, "错误", "验证失败")
                return
            send_secure_msg(sock, {"command": "register", "username": self.username_edit.text(), "password": self.password_edit.text()})
            resp = read_secure_msg(sock)
            QMessageBox.information(self, "结果", resp.get("message"))
            sock.close()
        except Exception as e: QMessageBox.warning(self, "错误", str(e))

    def login_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_ip_edit.text(), 12345))
            if not client_handshake(self.client_socket):
                QMessageBox.warning(self, "错误", "验证失败")
                return
            send_secure_msg(self.client_socket, {"command": "login", "username": self.username_edit.text(), "password": self.password_edit.text()})
            resp = read_secure_msg(self.client_socket)
            if resp.get("status") == "ok":
                self.receiver_thread = ChatReceiver(self.client_socket)
                self.receiver_thread.new_message.connect(self.update_chat)
                self.receiver_thread.update_online_users.connect(self.update_online_users)
                self.receiver_thread.notify_message.connect(lambda m: QMessageBox.information(self, "提示", m))
                self.receiver_thread.start()
                self.login_btn.setDisabled(True)
            else:
                QMessageBox.warning(self, "失败", resp.get("message"))
        except Exception as e: QMessageBox.warning(self, "错误", str(e))

    def send_message(self):
        msg = self.message_edit.text().strip()
        if not msg or not self.client_socket: return
        t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        u = self.username_edit.text()
        send_secure_msg(self.client_socket, {"username": u, "message": msg, "time": t})
        self.update_chat(f"You ({t}): {msg}")
        save_message_local(u, msg, "local", t)
        self.message_edit.clear()

    def sync_history(self):
        if self.client_socket:
            send_secure_msg(self.client_socket, {"command": "sync_history", "since": get_last_message_time()})

    def update_chat(self, msg):
        self.chat_area.append(msg)

    def update_online_users(self, count):
        self.online_users_label.setText(f"在线人数: {count}")

    def show_notification(self, msg):
        QMessageBox.information(self, "提示", msg)

    def disconnect_from_server(self):
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.client_socket.close()
            self.client_socket = None
        if self.receiver_thread:
            self.receiver_thread.stop()
            self.receiver_thread = None
        self.server_ip_edit.setDisabled(False)
        self.username_edit.setDisabled(False)
        self.password_edit.setDisabled(False)
        self.login_btn.setDisabled(False)
        self.register_btn.setDisabled(False)
        self.update_chat("已断开与服务器的连接。")

    def show_about(self):
        QMessageBox.information(self, "关于", '<a href="https://github.com/xhdndmm/meow-chat">meow-chat-user-v1.4</a>| By <a href="https://github.com/xhdndmm/">xhdndmm</a> | GPLv3 LICENSE')

    def closeEvent(self, event):
        if self.receiver_thread: self.receiver_thread.stop()
        if self.client_socket: self.client_socket.close()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
