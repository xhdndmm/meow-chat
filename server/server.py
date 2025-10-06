# server.py v1.2
# https://github.com/xhdndmm/meow-chat

import socket
import threading
import json
import os
import base64
import sqlite3
from datetime import datetime
import logging

logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DB_PATH = "server_data.db"
clients = []


# ---------------- 数据库初始化 ----------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # 用户表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            last_ip TEXT
        )
    """)
    # 聊天记录表
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
    """按时间同步缺失的聊天记录"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, message, ip, time FROM chat_history WHERE time > ? ORDER BY time ASC", (since,))
    rows = cur.fetchall()
    conn.close()
    data = [{"username": r[0], "message": r[1], "ip": r[2], "time": r[3]} for r in rows]
    payload = {"type": "history", "data": data}
    client_socket.sendall(base64.b64encode(json.dumps(payload).encode("utf-8")))


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


def send_to_client(message, client_socket):
    try:
        encrypted = base64.b64encode(message.encode('utf-8'))
        client_socket.sendall(encrypted)
    except Exception as e:
        logging.error(f"Send error: {e}")
        if client_socket in clients:
            clients.remove(client_socket)
        client_socket.close()


def broadcast(message, client_socket, data):
    """广播消息并保存"""
    for client in clients:
        if client != client_socket:
            send_to_client(message, client)
    save_message_to_db(data["username"], data["message"], data["ip"], data["time"])


def broadcast_online_users():
    count = len(clients)
    msg = json.dumps({"type": "online_users", "count": count})
    for client in clients:
        send_to_client(msg, client)


def handle_client(client_socket):
    global clients
    verified = False
    username = None
    while True:
        try:
            raw_message = read_message(client_socket)
            if not raw_message:
                break
            decoded = base64.b64decode(raw_message).decode("utf-8")
            data = json.loads(decoded)

            # 登录 / 注册
            if not verified:
                cmd = data.get("command")
                if cmd == "register":
                    ok = register_user(data["username"], data["password"])
                    if ok:
                        send_to_client(json.dumps({"type": "register", "status": "ok", "message": "注册成功"}), client_socket)
                    else:
                        send_to_client(json.dumps({"type": "register", "status": "fail", "message": "用户名已存在"}), client_socket)
                    continue
                elif cmd == "login":
                    ip = client_socket.getpeername()[0]
                    result = verify_user(data["username"], data["password"], ip)
                    if result["status"] == "ok":
                        verified = True
                        username = data["username"]
                        msg = {"type": "login", "status": "ok", "message": result["message"]}
                        send_to_client(json.dumps(msg), client_socket)
                        broadcast_online_users()
                    else:
                        send_to_client(json.dumps({"type": "login", "status": "fail", "message": result["message"]}), client_socket)
                    continue

            # 聊天记录同步
            if data.get("command") == "sync_history":
                since = data.get("since", "1970-01-01 00:00:00")
                send_sync_history(client_socket, since)
                continue

            # 普通消息
            data["ip"] = client_socket.getpeername()[0]
            if "time" not in data:
                data["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            msg_json = json.dumps(data)
            broadcast(msg_json, client_socket, data)

        except Exception as e:
            logging.error(f"Client error: {e}")
            break

    if client_socket in clients:
        clients.remove(client_socket)
        broadcast_online_users()
    client_socket.close()


# ---------------- 启动服务器 ----------------
def start_server():
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "12345"))
    server.bind((host, port))
    server.listen(5)
    logging.info(f"Server started on {host}:{port}")

    try:
        while True:
            client_socket, addr = server.accept()
            clients.append(client_socket)
            threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()
            logging.info(f"Connection from {addr}")
    except KeyboardInterrupt:
        logging.info("Server shutting down...")
    finally:
        for client in clients:
            try:
                client.close()
            except:
                pass
        server.close()


if __name__ == "__main__":
    start_server()
