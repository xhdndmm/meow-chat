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
    QLineEdit, QPushButton, QTextEdit, QLabel, QMessageBox, QCheckBox, QComboBox
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

# ---------------- 本地存储与客户端配置 ----------------
# 为每个服务器创建独立的表（表名基于服务器地址），并维护一个 `servers` 表用于记录服务器的元信息
CLIENT_CONFIG = "client_config.json"

def sanitize_name(s):
    # 将任意非字母数字字符替换为下划线，生成安全的表名
    import re
    return re.sub(r"[^0-9a-zA-Z]", "_", f"{s}")

def get_table_name(host, port):
    return f"chat_{sanitize_name(host)}_{port}"

def init_local_db():
    # 初始化本地数据库并确保 servers 表存在
    conn = sqlite3.connect(LOCAL_DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS servers (
            host TEXT,
            port INTEGER,
            username TEXT,
            last_sync TEXT,
            PRIMARY KEY (host, port)
        )
    """)
    conn.commit()
    conn.close()

def ensure_server_table(host, port):
    table = get_table_name(host, port)
    conn = sqlite3.connect(LOCAL_DB)
    cur = conn.cursor()
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {table} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            message TEXT,
            ip TEXT,
            time TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_message_local(host, port, username, message, ip, time):
    # 保存消息到对应服务器的表，并更新 servers.last_sync
    ensure_server_table(host, port)
    table = get_table_name(host, port)
    conn = sqlite3.connect(LOCAL_DB)
    cur = conn.cursor()
    cur.execute(f"INSERT INTO {table} (username, message, ip, time) VALUES (?, ?, ?, ?)", (username, message, ip, time))
    # 更新 last_sync
    cur.execute("INSERT OR REPLACE INTO servers (host, port, username, last_sync) VALUES (?, ?, ?, ?)", (host, port, username, time))
    conn.commit()
    conn.close()

def get_last_message_time(host, port):
    # 返回特定服务器的最后消息时间，用于按日期增量同步
    table = get_table_name(host, port)
    conn = sqlite3.connect(LOCAL_DB)
    cur = conn.cursor()
    # 如果表不存在则返回最早时间
    try:
        cur.execute(f"SELECT time FROM {table} ORDER BY time DESC LIMIT 1")
        row = cur.fetchone()
        if row:
            return row[0]
    except sqlite3.OperationalError:
        pass
    # 如果没有消息则尝试读取 servers 表的 last_sync
    cur.execute("SELECT last_sync FROM servers WHERE host = ? AND port = ?", (host, port))
    row = cur.fetchone()
    conn.close()
    return row[0] if row and row[0] else "1970-01-01 00:00:00"

# 客户端配置读写（记录服务器、用户名、上次同步时间等，可由用户选择是否记录）
def load_client_config():
    if not os.path.exists(CLIENT_CONFIG):
        return {"servers": []}
    try:
        with open(CLIENT_CONFIG, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"servers": []}

def save_client_config(cfg):
    with open(CLIENT_CONFIG, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

def add_server_to_config(host, port, username, last_sync=None):
    cfg = load_client_config()
    servers = cfg.get("servers", [])
    # 如果已存在则更新
    for s in servers:
        if s.get("host") == host and int(s.get("port")) == int(port):
            s["username"] = username
            if last_sync: s["last_sync"] = last_sync
            save_client_config(cfg)
            return
    servers.append({"host": host, "port": port, "username": username, "last_sync": last_sync or "1970-01-01 00:00:00"})
    cfg["servers"] = servers
    save_client_config(cfg)

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

    def __init__(self, client_socket, server_key):
        super().__init__()
        self.client_socket = client_socket
        self.server_key = server_key  # (host, port)
        self.running = True

    def run(self):
        while self.running:
            try:
                data = read_secure_msg(self.client_socket)
                if not data: break
                if data.get("type") == "history":
                    for msg in data["data"]:
                        # 保存到对应服务器的本地表，显示时包含 IP
                        save_message_local(self.server_key[0], self.server_key[1], msg["username"], msg["message"], msg.get("ip", ""), msg["time"])
                        text = f"{msg['username']} @{msg.get('ip','')} ({msg['time']}): {msg['message']}"
                        self.new_message.emit(text)
                elif data.get("type") == "online_users":
                    self.update_online_users.emit(data["count"])
                elif data.get("type") == "login":
                    if data.get("message"): self.notify_message.emit(data["message"])
                else:
                    save_message_local(self.server_key[0], self.server_key[1], data["username"], data["message"], data.get("ip", ""), data.get("time", ""))
                    text = f"{data['username']} @{data.get('ip','')} ({data.get('time', 'unknown')}): {data['message']}"
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

        # 连接区（服务器输入为可编辑下拉，可记住服务器信息）
        h_conn = QHBoxLayout()
        h_conn.addWidget(QLabel("服务器地址:"))
        self.server_combo = QComboBox()
        self.server_combo.setEditable(True)
        h_conn.addWidget(self.server_combo)
        self.remember_chk = QCheckBox("记住此服务器")
        h_conn.addWidget(self.remember_chk)

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

        # 加载客户端配置并填充下拉项
        cfg = load_client_config()
        for s in cfg.get("servers", []):
            self.server_combo.addItem(f"{s.get('host')}:{s.get('port')}")


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

    def parse_host_port(self, text):
        # 支持 "host" 或 "host:port" 两种写法，默认为 12345 端口
        if not text:
            return None, None
        if ":" in text:
            parts = text.split(":")
            return parts[0], int(parts[1]) if parts[1].isdigit() else 12345
        return text, 12345

    def register_account(self):
        try:
            host, port = self.parse_host_port(self.server_combo.currentText())
            if not host: raise ValueError("无效的服务器地址")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
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
            host, port = self.parse_host_port(self.server_combo.currentText())
            if not host: raise ValueError("无效的服务器地址")
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))
            if not client_handshake(self.client_socket):
                QMessageBox.warning(self, "错误", "验证失败")
                return
            send_secure_msg(self.client_socket, {"command": "login", "username": self.username_edit.text(), "password": self.password_edit.text()})
            resp = read_secure_msg(self.client_socket)
            if resp.get("status") == "ok":
                # 记录当前连接的服务器信息
                self.current_host = host
                self.current_port = port
                # 确保本地表存在
                ensure_server_table(host, port)
                # 启动接收线程（传入服务器键以便保存消息到对应表）
                self.receiver_thread = ChatReceiver(self.client_socket, (host, port))
                self.receiver_thread.new_message.connect(self.update_chat)
                self.receiver_thread.update_online_users.connect(self.update_online_users)
                self.receiver_thread.notify_message.connect(lambda m: QMessageBox.information(self, "提示", m))
                self.receiver_thread.start()
                self.login_btn.setDisabled(True)
                # 若用户选择记住服务器，则保存到配置文件
                if self.remember_chk.isChecked():
                    add_server_to_config(host, port, self.username_edit.text(), get_last_message_time(host, port))
                    # 如果下拉中没有则添加
                    item_text = f"{host}:{port}"
                    if self.server_combo.findText(item_text) == -1:
                        self.server_combo.addItem(item_text)
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
        if self.client_socket and getattr(self, 'current_host', None):
            since = get_last_message_time(self.current_host, self.current_port)
            send_secure_msg(self.client_socket, {"command": "sync_history", "since": since})

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
        self.server_combo.setDisabled(False)
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
