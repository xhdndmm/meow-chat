# server.py v1.5
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
from concurrent.futures import ThreadPoolExecutor
import queue
import time

# 读取服务端配置（支持自定义日志文件、数据库存储路径、监听地址与端口）
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'server_config.json')

def load_server_config():
    #如果配置文件不存在则写入默认配置，返回配置字典
    default = {
        "host": "0.0.0.0",
        "port": 12345,
        "db_path": "server_data.db",
        "log_file": "server.log",
        "log_level": "INFO"
    }
    try:
        if not os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                json.dump(default, f, indent=2, ensure_ascii=False)
            return default
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
            # 合并默认值并返回
            merged = default.copy()
            merged.update(cfg)
            return merged
    except Exception as e:
        # 配置读取失败则退回默认配置
        print(f"加载 server_config.json 失败：{e}")
        return default

cfg = load_server_config()
DB_PATH = cfg.get('db_path', 'server_data.db')
LOG_FILE = cfg.get('log_file', 'server.log')
LOG_LEVEL = getattr(logging, cfg.get('log_level', 'INFO').upper(), logging.INFO)
clients = []
clients_lock = threading.Lock()
message_queue = queue.Queue()
shutdown_event = threading.Event()
executor = None

# 配置日志（使用配置文件指定的日志文件与级别）
logging.basicConfig(filename=LOG_FILE, level=LOG_LEVEL, format='%(asctime)s - %(levelname)s - %(message)s')

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
    # 创建时间索引以便按时间范围查询更快
    cur.execute("CREATE INDEX IF NOT EXISTS idx_chat_time ON chat_history(time)")
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


def db_worker():
    """后台数据库写入线程，批量写入以提升吞吐并减少主线程阻塞"""
    batch = []
    last_flush = time.time()
    while not shutdown_event.is_set() or not message_queue.empty():
        try:
            msg = message_queue.get(timeout=0.5)
            batch.append(msg)
            # 批量写入：达到 50 条或超过 1 秒则写入
            if len(batch) >= 50 or (time.time() - last_flush) >= 1.0:
                conn = sqlite3.connect(DB_PATH)
                cur = conn.cursor()
                cur.executemany("INSERT INTO chat_history (username, message, ip, time) VALUES (?, ?, ?, ?)",
                                [(m.get("username"), m.get("message"), m.get("ip", ""), m.get("time", "")) for m in batch])
                conn.commit()
                conn.close()
                batch = []
                last_flush = time.time()
        except queue.Empty:
            # 空时仍需检查是否有待写入的残留
            if batch:
                conn = sqlite3.connect(DB_PATH)
                cur = conn.cursor()
                cur.executemany("INSERT INTO chat_history (username, message, ip, time) VALUES (?, ?, ?, ?)",
                                [(m.get("username"), m.get("message"), m.get("ip", ""), m.get("time", "")) for m in batch])
                conn.commit()
                conn.close()
                batch = []
                last_flush = time.time()
    # 退出前再 flush 一次
    if batch:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.executemany("INSERT INTO chat_history (username, message, ip, time) VALUES (?, ?, ?, ?)",
                        [(m.get("username"), m.get("message"), m.get("ip", ""), m.get("time", "")) for m in batch])
        conn.commit()
        conn.close()

# ---------------- 网络通信 ----------------
def broadcast(message_data, client_socket):
    # 复制一份目标客户端列表，避免在发送时修改原列表
    with clients_lock:
        targets = [c for c in clients if c != client_socket]
    for client in targets:
        try:
            send_secure_msg(client, message_data)
        except Exception as e:
            try:
                addr = client.getpeername()
            except Exception:
                addr = '<unknown>'
            logging.warning(f"Failed to send to {addr}: {e}")
            with clients_lock:
                if client in clients:
                    clients.remove(client)
    # 将消息放入队列由后台 DB 线程异步写入，减少 IO 阻塞
    try:
        message_queue.put_nowait(message_data)
    except queue.Full:
        logging.error("Message queue full, dropping message")

def broadcast_online_users():
    with clients_lock:
        snapshot = list(clients)
    count = len(snapshot)
    payload = {"type": "online_users", "count": count}
    for client in snapshot:
        try:
            send_secure_msg(client, payload)
        except Exception:
            # 忽略单个发送失败
            pass

def handle_client(client_socket):
    global clients
    verified = False
    username = None
    # 给每个连接设置超时以避免长期占用资源（可配置）
    try:
        client_socket.settimeout(300)
    except Exception:
        pass

    try:
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

            except socket.timeout:
                logging.info("Client socket timeout, closing connection")
                break
            except Exception as e:
                logging.error(f"Client error: {e}")
                break
    finally:
        # 确保移除并通知在线人数变化
        with clients_lock:
            if client_socket in clients:
                clients.remove(client_socket)
        broadcast_online_users()
        try:
            client_socket.close()
        except Exception:
            pass

def start_server():
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # 优先使用环境变量，其次使用配置文件中的 host/port
    host = os.getenv("HOST", cfg.get('host', '0.0.0.0'))
    port = int(os.getenv("PORT", cfg.get('port', 12345)))
    server.bind((host, port))
    server.listen(5)
    logging.info("Meow-Chat-Server-v1.5")
    logging.info(f"Server started on {host}:{port} (config: {CONFIG_PATH})")

    # 启动后台 DB 写入线程
    db_thread = threading.Thread(target=db_worker, daemon=True)
    db_thread.start()

    # 使用线程池来管理客户端线程数，避免无限制创建线程
    max_workers = int(os.getenv('MAX_WORKERS', cfg.get('max_workers', 100)))
    global executor
    executor = ThreadPoolExecutor(max_workers=max_workers)

    try:
        while True:
            client_socket, addr = server.accept()
            if not verify_client_handshake(client_socket):
                logging.warning(f"Client {addr} failed verification")
                client_socket.close()
                continue

            # 添加到客户端列表（线程安全）
            with clients_lock:
                clients.append(client_socket)
            # 使用线程池提交任务
            executor.submit(handle_client, client_socket)
            logging.info(f"Connection from {addr}")
    except KeyboardInterrupt:
        logging.info("Server shutting down...")
        shutdown_event.set()
    finally:
        # 先关闭服务器 socket，然后关停线程池并等待 DB 线程刷盘
        try:
            server.close()
        except Exception:
            pass
        if executor:
            executor.shutdown(wait=True)
        # 等待 DB 线程完成未写入的消息
        shutdown_event.set()
        db_thread.join(timeout=2)
        logging.info("Server stopped")

if __name__ == "__main__":
    start_server()
