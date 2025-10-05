# server.pyc

import socket
import threading
import json
import os
import base64
import sqlite3
from datetime import datetime
import logging

logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DB_PATH = "users.db"

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
    conn.commit()
    conn.close()

if os.path.exists("chat.json"):
    try:
        with open("chat.json", "r") as file:
            MESSAGE_LOG = json.load(file)
    except Exception:
        MESSAGE_LOG = []
else:
    MESSAGE_LOG = []

clients = []

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

def handle_client(client_socket):
    global clients
    verified = False
    username = None
    while True:
        try:
            raw_message = read_message(client_socket)
            if not raw_message:
                break
            decoded = base64.b64decode(raw_message).decode('utf-8')
            data = json.loads(decoded)

            if not verified:
                cmd = data.get("command")
                if cmd == "register":
                    if register_user(data["username"], data["password"]):
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
                else:
                    send_to_client(json.dumps({"type": "fail", "message": "未验证的命令"}), client_socket)
                    break

            if data.get("command") == "load_history":
                send_chat_history(client_socket)
                continue

            data["ip"] = client_socket.getpeername()[0]
            if "time" not in data:
                data["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            processed_message = json.dumps(data)
            broadcast(processed_message, client_socket, data)
        except Exception as e:
            logging.error(f"Client error: {e}")
            break
    if client_socket in clients:
        clients.remove(client_socket)
        broadcast_online_users()
    client_socket.close()

def broadcast_online_users():
    global clients
    count = len(clients)
    message = json.dumps({"type": "online_users", "count": count})
    for client in clients:
        send_to_client(message, client)

def save_message_to_file(username, message, ip, time):
    global MESSAGE_LOG
    MESSAGE_LOG.append({"username": username, "message": message, "ip": ip, "time": time})
    with open("chat.json", "w") as file:
        json.dump(MESSAGE_LOG, file, ensure_ascii=False, indent=4)

def broadcast(message, client_socket, data):
    for client in clients:
        if client != client_socket:
            send_to_client(message, client)
    save_message_to_file(data["username"], data["message"], data["ip"], data["time"])

def send_to_client(message, client_socket):
    try:
        encrypted = base64.b64encode(message.encode('utf-8'))
        client_socket.sendall(encrypted)
    except Exception as e:
        logging.error(f"Send error: {e}")
        if client_socket in clients:
            clients.remove(client_socket)
        client_socket.close()

def send_chat_history(client_socket):
    try:
        history_payload = {"type": "history", "data": MESSAGE_LOG}
        json_payload = json.dumps(history_payload)
        encrypted = base64.b64encode(json_payload.encode('utf-8'))
        client_socket.sendall(encrypted)
    except Exception as e:
        logging.error(f"Error sending history: {e}")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "12345"))
    server.bind((host, port))
    server.listen(5)
    server.settimeout(1)
    logging.info(f"Server started on {host}:{port}")

    shutdown_flag = False
    try:
        while not shutdown_flag:
            try:
                client_socket, addr = server.accept()
                logging.info(f"Connection from {addr}")
                clients.append(client_socket)
                threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()
            except socket.timeout:
                pass
    except KeyboardInterrupt:
        logging.info("Server shutting down manually...")
    finally:
        for client in clients:
            try:
                client.close()
            except Exception:
                pass
        server.close()
        logging.info("Server closed.")

if __name__ == "__main__":
    init_db()
    start_server()
