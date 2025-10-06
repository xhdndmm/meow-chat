# user.py v1.2
# https://github.com/xhdndmm/meow-chat

import sys
import socket
import json
import base64
import sqlite3
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QTextEdit, QLabel, QMessageBox
)
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QAction

LOCAL_DB = "local_chat.db"


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


# ---------------- 网络通信 ----------------
def read_message(sock):
    buffer = bytearray()
    while True:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buffer.extend(chunk)
        if len(chunk) < 1024:
            break
    return bytes(buffer)


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
                combined = read_message(self.client_socket)
                if not combined:
                    break
                decoded = base64.b64decode(combined).decode("utf-8")
                data = json.loads(decoded)
                if data.get("type") == "history":
                    for msg in data["data"]:
                        text = f"{msg['username']} ({msg['time']}, {msg.get('ip', 'unknown')}): {msg['message']}"
                        save_message_local(msg["username"], msg["message"], msg.get("ip", ""), msg["time"])
                        self.new_message.emit(text)
                elif data.get("type") == "online_users":
                    self.update_online_users.emit(data["count"])
                elif data.get("type") == "login":
                    if data.get("message"):
                        self.notify_message.emit(data["message"])
                else:
                    text = f"{data['username']} ({data.get('time', 'unknown')}, {data.get('ip', 'unknown')}): {data['message']}"
                    save_message_local(data["username"], data["message"], data.get("ip", ""), data.get("time", ""))
                    self.new_message.emit(text)
            except Exception:
                break

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
        self.setWindowTitle("meow-chat-user-v1.2")
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
        h_msg.addWidget(self.message_edit)
        self.send_btn = QPushButton("发送")
        self.send_btn.clicked.connect(self.send_message)
        h_msg.addWidget(self.send_btn)
        v_layout.addLayout(h_msg)

        central.setLayout(v_layout)

    # 登录注册逻辑
    def register_account(self):
        server_ip = self.server_ip_edit.text().strip()
        username = self.username_edit.text().strip()
        password = self.password_edit.text().strip()
        if not server_ip or not username or not password:
            QMessageBox.warning(self, "警告", "请输入服务器地址、用户名和密码")
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((server_ip, 12345))
            payload = {"command": "register", "username": username, "password": password}
            sock.sendall(base64.b64encode(json.dumps(payload).encode("utf-8")))
            resp = json.loads(base64.b64decode(read_message(sock)).decode("utf-8"))
            QMessageBox.information(self, "注册结果", resp.get("message", "未知"))
            sock.close()
        except Exception as e:
            QMessageBox.warning(self, "错误", f"注册失败: {e}")

    def login_to_server(self):
        server_ip = self.server_ip_edit.text().strip()
        username = self.username_edit.text().strip()
        password = self.password_edit.text().strip()
        if not server_ip or not username or not password:
            QMessageBox.warning(self, "警告", "请输入服务器地址、用户名和密码")
            return
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((server_ip, 12345))
            payload = {"command": "login", "username": username, "password": password}
            self.client_socket.sendall(base64.b64encode(json.dumps(payload).encode("utf-8")))
            resp = json.loads(base64.b64decode(read_message(self.client_socket)).decode("utf-8"))
            if resp.get("status") != "ok":
                QMessageBox.warning(self, "登录失败", resp.get("message", "未知错误"))
                self.client_socket.close()
                self.client_socket = None
                return
            QMessageBox.information(self, "提示", resp.get("message", "登录成功"))
            self.server_ip_edit.setDisabled(True)
            self.username_edit.setDisabled(True)
            self.password_edit.setDisabled(True)
            self.login_btn.setDisabled(True)
            self.register_btn.setDisabled(True)
            self.receiver_thread = ChatReceiver(self.client_socket)
            self.receiver_thread.new_message.connect(self.update_chat)
            self.receiver_thread.update_online_users.connect(self.update_online_users)
            self.receiver_thread.notify_message.connect(self.show_notification)
            self.receiver_thread.start()
        except Exception as e:
            QMessageBox.warning(self, "错误", f"连接服务器失败: {e}")

    # 聊天逻辑
    def send_message(self):
        message = self.message_edit.text().strip()
        if not message or not self.client_socket:
            return
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        username = self.username_edit.text().strip()
        payload = {"username": username, "message": message, "time": current_time}
        try:
            self.client_socket.sendall(base64.b64encode(json.dumps(payload).encode("utf-8")))
            self.update_chat(f"You ({current_time}): {message}")
            save_message_local(username, message, "local", current_time)
        except Exception:
            QMessageBox.warning(self, "发送错误", "消息发送失败")
        self.message_edit.clear()

    def sync_history(self):
        if not self.client_socket:
            QMessageBox.warning(self, "警告", "尚未连接服务器")
            return
        try:
            since = get_last_message_time()
            payload = {"command": "sync_history", "since": since}
            self.client_socket.sendall(base64.b64encode(json.dumps(payload).encode("utf-8")))
        except Exception:
            QMessageBox.warning(self, "错误", "同步聊天记录失败")

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
        QMessageBox.information(self, "关于", '<a href="https://github.com/xhdndmm/meow-chat">meow-chat-user-v1.2</a>')

    def closeEvent(self, event):
        if self.receiver_thread:
            self.receiver_thread.stop()
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                pass
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
