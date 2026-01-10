# server.py v1.4
# https://github.com/xhdndmm/meow-chat

import socket
import threading
import json
import os
import sqlite3
from datetime import datetime
import logging
import hmac
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DB_PATH = "server_data.db"
clients = []

# --- 安全配置 ---
# 必须与客户端一致，且为32字节
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

# ---------------- 数据库初始化 ----------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            last_ip TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            message TEXT,
            ip TEXT,
            time TEXT
        )
    """)
    conn.commit()
    conn.close()

# --------------- 客户端校验 ----------------
def hmac_sha256(key, msg):
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()

def verify_client_handshake(client_socket):
    try:
        # 1. 等待 HELLO
        data = read_secure_msg(client_socket)
        if not data or data.get("type") != "hello":
            return False

        # 2. 发送 challenge
        challenge = secrets.token_hex(16)
        payload = {"type": "challenge", "challenge": challenge}
        send_secure_msg(client_socket, payload)

        # 3. 接收 response
        resp = read_secure_msg(client_socket)
        expected = hmac_sha256(SHARED_SECRET, challenge)
        return resp.get("type") == "response" and resp.get("hmac") == expected
    except Exception as e:
        logging.error(f"Handshake failed: {e}")
        return False

# ---------------- 用户注册 / 登录 ----------------
def register_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_user(username, password, ip):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT password, last_ip FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if row is None:
        conn.close()
        return {"status": "fail", "message": "用户不存在"}
    stored_password, last_ip = row
    if stored_password != password:
        conn.close()
        return {"status": "fail", "message": "密码错误"}
    message = None
    if last_ip != ip:
        message = f"检测到新 IP 登录：{ip}（上次为 {last_ip or '无记录'}）"
    cur.execute("UPDATE users SET last_ip = ? WHERE username = ?", (ip, username))
    conn.commit()
    conn.close()
    return {"status": "ok", "message": message}

# ---------------- 聊天记录操作 ----------------
def save_message_to_db(username, message, ip, time):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO chat_history (username, message, ip, time) VALUES (?, ?, ?, ?)",
                (username, message, ip, time))
    conn.commit()
    conn.close()

def send_sync_history(client_socket, since):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, message, ip, time FROM chat_history WHERE time > ? ORDER BY time ASC", (since,))
    rows = cur.fetchall()
    conn.close()
    data = [{"username": r[0], "message": r[1], "ip": r[2], "time": r[3]} for r in rows]
    payload = {"type": "history", "data": data}
    send_secure_msg(client_socket, payload)

# ---------------- 网络通信 ----------------
def broadcast(message_data, client_socket):
    for client in clients:
        if client != client_socket:
            try:
                send_secure_msg(client, message_data)
            except:
                if client in clients: clients.remove(client)
    save_message_to_db(message_data["username"], message_data["message"], message_data["ip"], message_data["time"])

def broadcast_online_users():
    count = len(clients)
    payload = {"type": "online_users", "count": count}
    for client in clients:
        try:
            send_secure_msg(client, payload)
        except:
            pass

def handle_client(client_socket):
    global clients
    verified = False
    username = None
    while True:
        try:
            data = read_secure_msg(client_socket)
            if not data:
                break

            if not verified:
                cmd = data.get("command")
                if cmd == "register":
                    ok = register_user(data["username"], data["password"])
                    resp = {"type": "register", "status": "ok" if ok else "fail", "message": "注册成功" if ok else "用户名已存在"}
                    send_secure_msg(client_socket, resp)
                    continue
                elif cmd == "login":
                    ip = client_socket.getpeername()[0]
                    result = verify_user(data["username"], data["password"], ip)
                    if result["status"] == "ok":
                        verified = True
                        username = data["username"]
                        msg = {"type": "login", "status": "ok", "message": result["message"]}
                        send_secure_msg(client_socket, msg)
                        broadcast_online_users()
                    else:
                        send_secure_msg(client_socket, {"type": "login", "status": "fail", "message": result["message"]})
                    continue

            if data.get("command") == "sync_history":
                since = data.get("since", "1970-01-01 00:00:00")
                send_sync_history(client_socket, since)
                continue

            data["ip"] = client_socket.getpeername()[0]
            if "time" not in data:
                data["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            broadcast(data, client_socket)

        except Exception as e:
            logging.error(f"Client error: {e}")
            break

    if client_socket in clients:
        clients.remove(client_socket)
        broadcast_online_users()
    client_socket.close()

def start_server():
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "12345"))
    server.bind((host, port))
    server.listen(5)
    logging.info("Meow-Chat-Server-v1.4")
    logging.info(f"Server started on {host}:{port}")

    try:
        while True:
            client_socket, addr = server.accept()
            if not verify_client_handshake(client_socket):
                logging.warning(f"Client {addr} failed verification")
                client_socket.close()
                continue

            clients.append(client_socket)
            threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()
            logging.info(f"Connection from {addr}")
    except KeyboardInterrupt:
        logging.info("Server shutting down...")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()
