#https://github.com/xhdndmm/meow-chat

import sys
import socket
import json
import base64
from datetime import datetime
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QTextEdit, QLabel, QMessageBox
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QAction

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
                decoded = base64.b64decode(combined).decode('utf-8')
                data = json.loads(decoded)
                if data.get("type") == "history":
                    for msg in data["data"]:
                        text = f"{msg['username']} ({msg['time']}, {msg.get('ip', 'unknown')}): {msg['message']}"
                        self.new_message.emit(text)
                elif data.get("type") == "online_users":
                    self.update_online_users.emit(data["count"])
                else:
                    text = f"{data['username']} ({data.get('time', 'unknown')}, {data.get('ip', 'unknown')}): {data['message']}"
                    self.new_message.emit(text)
            except Exception as e:
                break

    def stop(self):
        self.running = False
        self.quit()
        self.wait()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowOpacity(0.95)
        self.init_ui()
        toolbar = self.addToolBar("功能栏")
        toolbar.setMovable(False)
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about)
        toolbar.addAction(about_action)
        self.online_users_label = QLabel("在线人数: 0")
        toolbar.addWidget(self.online_users_label)
        self.client_socket = None
        self.receiver_thread = None

    def init_ui(self):
        self.setWindowTitle("meow-chat-user-v1.0")
        central = QWidget()
        self.setCentralWidget(central)
        v_layout = QVBoxLayout()
        h_conn = QHBoxLayout()
        h_conn.addWidget(QLabel("服务器地址:"))
        self.server_ip_edit = QLineEdit()
        h_conn.addWidget(self.server_ip_edit)
        h_conn.addWidget(QLabel("用户名:"))
        self.username_edit = QLineEdit()
        h_conn.addWidget(self.username_edit)
        self.connect_btn = QPushButton("连接")
        self.connect_btn.clicked.connect(self.connect_to_server)
        h_conn.addWidget(self.connect_btn)
        v_layout.addLayout(h_conn)
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        v_layout.addWidget(self.chat_area)
        h_load = QHBoxLayout()
        self.load_history_btn = QPushButton("加载聊天记录")
        self.load_history_btn.clicked.connect(self.load_history)
        h_load.addWidget(self.load_history_btn)
        self.disconnect_btn = QPushButton("断开连接")
        self.disconnect_btn.clicked.connect(self.disconnect_from_server)
        h_load.addWidget(self.disconnect_btn)
        v_layout.addLayout(h_load)
        h_msg = QHBoxLayout()
        self.message_edit = QLineEdit()
        h_msg.addWidget(self.message_edit)
        self.send_btn = QPushButton("发送")
        self.send_btn.clicked.connect(self.send_message)
        h_msg.addWidget(self.send_btn)
        v_layout.addLayout(h_msg)
        central.setLayout(v_layout)
        
    def connect_to_server(self):
        server_ip = self.server_ip_edit.text().strip()
        username = self.username_edit.text().strip()
        if not server_ip or not username:
            QMessageBox.warning(self, "警告", "请输入服务器地址和用户名")
            return
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((server_ip, 12345))
            verify_payload = {"command": "verify", "payload": "meow-chat-v1.0"}
            json_verify = json.dumps(verify_payload)
            encrypted_verify = base64.b64encode(json_verify.encode('utf-8'))
            self.client_socket.sendall(encrypted_verify)
            self.client_socket.settimeout(5)
            response_data = read_message(self.client_socket)
            self.client_socket.settimeout(None)
            if not response_data:
                raise Exception("未收到验证响应")
            decoded_resp = base64.b64decode(response_data).decode('utf-8')
            resp = json.loads(decoded_resp)
            if not (resp.get("type") == "verify" and resp.get("status") == "ok"):
                QMessageBox.warning(self, "验证失败", f"服务器验证失败: {resp.get('message', '未知错误')}")
                self.client_socket.close()
                self.client_socket = None
                self.server_ip_edit.setDisabled(False)
                self.username_edit.setDisabled(False)
                self.connect_btn.setDisabled(False)
                return
        except Exception as e:
            QMessageBox.warning(self, "验证失败", f"服务器验证异常: {str(e)}")
            if self.client_socket:
                self.client_socket.close()
            self.client_socket = None
            self.server_ip_edit.setDisabled(False)
            self.username_edit.setDisabled(False)
            self.connect_btn.setDisabled(False)
            return
        self.server_ip_edit.setDisabled(True)
        self.username_edit.setDisabled(True)
        self.connect_btn.setDisabled(True)
        self.receiver_thread = ChatReceiver(self.client_socket)
        self.receiver_thread.new_message.connect(self.update_chat)
        self.receiver_thread.update_online_users.connect(self.update_online_users)
        self.receiver_thread.start()
        
    def send_message(self):
        message = self.message_edit.text().strip()
        if not message:
            return
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        username = self.username_edit.text().strip()
        payload = {"username": username, "message": message, "time": current_time}
        json_payload = json.dumps(payload)
        try:
            encrypted = base64.b64encode(json_payload.encode('utf-8'))
            self.client_socket.sendall(encrypted)
            self.update_chat(f"You ({current_time}): {message}")
        except Exception as e:
            QMessageBox.warning(self, "发送错误", "消息发送失败")
        self.message_edit.clear()
        
    def load_history(self):
        if not self.client_socket:
            QMessageBox.warning(self, "警告", "尚未连接服务器")
            return
        self.chat_area.clear()
        try:
            payload = {"command": "load_history"}
            json_payload = json.dumps(payload)
            encrypted = base64.b64encode(json_payload.encode('utf-8'))
            self.client_socket.sendall(encrypted)
        except Exception as e:
            QMessageBox.warning(self, "加载错误", "加载聊天记录失败")
        
    def update_chat(self, msg):
        self.chat_area.append(msg)
        
    def update_online_users(self, count):
        self.online_users_label.setText(f"在线人数: {count}")
        
    def disconnect_from_server(self):
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.client_socket.close()
            except Exception:
                pass
            self.client_socket = None
        if self.receiver_thread:
            self.receiver_thread.stop()
            self.receiver_thread = None
        self.server_ip_edit.setDisabled(False)
        self.username_edit.setDisabled(False)
        self.connect_btn.setDisabled(False)
        self.update_chat("已断开与服务器的连接。")
        
    def show_about(self):
        QMessageBox.information(self, "关于", '<a href="https://github.com/xhdndmm/meow-chat">meow-chat-user-v1.0</a>')
        
    def closeEvent(self, event):
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
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