import os
import re
import json
import time
import socket
import struct
import secrets
import datetime
import threading
import requests
from enum import Enum
from typing import Any, Tuple
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify

from Crypto.Cipher import AES
import zstandard as zstd

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ── KONFIGURASI & DATABASE ───────────────────────────────────────────
DATA_FILE = "web_data.json"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123" # Ganti password admin ini

BAN_API_KEY = "XdzVwcnvQAPhGXFbBhCuKfHRjMTFaDlEvSS7O2C7oMo"
BAN_URL = "https://checkton.online/backend/device_id"
INFO_API_KEY = "XdzVwcnvQAPhGXFbBhCuKfHRjMTFaDlEvSS7O2C7oMo"
INFO_URL = "https://checkton.online/backend/info"

# In-memory task tracking untuk progress realtime
TASKS = {}

def load_db():
    if not os.path.exists(DATA_FILE):
        return {"users": {ADMIN_USERNAME: {"password": ADMIN_PASSWORD, "role": "admin", "expiry": 9999999999}}, "redeems": {}}
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except:
        return {"users": {ADMIN_USERNAME: {"password": ADMIN_PASSWORD, "role": "admin", "expiry": 9999999999}}, "redeems": {}}

def save_db(db):
    with open(DATA_FILE, "w") as f:
        json.dump(db, f, indent=4)

# ── MLBB ENGINE (Dari device_login.py) ───────────────────────────────
AES_KEY = bytes.fromhex('f5a193d50ade553e9835595f5cd75ddd')
AES_IV = b'\x00' * 16

class SdpDataType(Enum):
    INTEGER_POSITIVE = 0
    INTEGER_NEGATIVE = 1
    FLOAT = 2
    DOUBLE = 3
    STRING = 4
    LIST = 5
    DICT = 6
    STRUCT_BEGIN = 7
    STRUCT_END = 8

class SdpStruct(dict):
    def __init__(self, data=None):
        super().__init__()
        self.data = b''
        self.offset = 0
        if isinstance(data, bytes):
            self.data = data
            self._unpack_from_binary()
        elif data is not None:
            super().update(data)
            self._pack_to_binary()
    
    def _pack_to_binary(self):
        self.data = bytes([SdpDataType.STRUCT_BEGIN.value << 4])
        for tag, value in sorted(self.items()): self._pack(tag, value)
        self.data += bytes([SdpDataType.STRUCT_END.value << 4])
    
    def _unpack_from_binary(self):
        if not self.data: return
        if self.data[0] >> 4 == SdpDataType.STRUCT_BEGIN.value: self.offset = 1
        while self.offset < len(self.data):
            tag, value = self._unpack()
            if isinstance(value, SdpDataType) and value == SdpDataType.STRUCT_END: break
            self[tag] = value
            
    def _write_number(self, value: int) -> bytes:
        result = bytearray()
        while value >= 0x80:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)
    
    def _read_number(self) -> int:
        n = 1
        val = self.data[self.offset] & 0x7F
        while self.data[self.offset + n - 1] >= 0x80:
            val |= (self.data[self.offset + n] & 0x7F) << (7 * n)
            n += 1
        self.offset += n
        return val
    
    def _pack_header(self, tag: int, data_type: SdpDataType) -> None:
        if tag < 15: self.data += bytes([(data_type.value << 4) | tag])
        else:
            self.data += bytes([(data_type.value << 4) | 15])
            self.data += self._write_number(tag)
    
    def _pack(self, tag: int, value: Any) -> None:
        if isinstance(value, bool):
            self._pack_header(tag, SdpDataType.INTEGER_POSITIVE)
            self.data += self._write_number(1 if value else 0)
        elif isinstance(value, int):
            if value < 0:
                self._pack_header(tag, SdpDataType.INTEGER_NEGATIVE)
                self.data += self._write_number(-value)
            else:
                self._pack_header(tag, SdpDataType.INTEGER_POSITIVE)
                self.data += self._write_number(value)
        elif isinstance(value, str) or isinstance(value, bytes):
            self._pack_header(tag, SdpDataType.STRING)
            encoded = value.encode('utf-8') if isinstance(value, str) else value
            self.data += self._write_number(len(encoded))
            self.data += encoded

    def _unpack(self) -> Tuple[int, Any]:
        try:
            if self.offset >= len(self.data): return 0, None
            header = self.data[self.offset]
            tag = header & 0xF
            data_type = SdpDataType(header >> 4)
            self.offset += 1
            if tag == 15: tag = self._read_number()
            
            if data_type == SdpDataType.INTEGER_POSITIVE: return tag, self._read_number()
            elif data_type == SdpDataType.INTEGER_NEGATIVE: return tag, -self._read_number()
            elif data_type == SdpDataType.STRING:
                length = self._read_number()
                val = self.data[self.offset:self.offset+length].decode('utf-8', errors='ignore')
                self.offset += length
                return tag, val
            elif data_type == SdpDataType.STRUCT_BEGIN:
                struct_data = {}
                while True:
                    sub_tag, sub_val = self._unpack()
                    if isinstance(sub_val, SdpDataType) and sub_val == SdpDataType.STRUCT_END: break
                    struct_data[sub_tag] = sub_val
                return tag, SdpStruct(struct_data)
            elif data_type == SdpDataType.STRUCT_END: return tag, SdpDataType.STRUCT_END
            else: return tag, None
        except: return 0, None

class GameLogin:
    def __init__(self, device_id):
        self.host = 'login.ml.youngjoygame.com'
        self.port = 30021
        self.device_id = device_id
        self.sequence = 1
        self.socket = None
        self.queue_data = b''
        parts = device_id.split('_')
        self.imei_md5 = parts[1] if len(parts) > 1 else device_id
        self.android_id = ""
        self.advertising_id = ""

    def run(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.socket.settimeout(5)
            
            sdp = SdpStruct({
                0: self.device_id,
                1: f'gps_adid={self.advertising_id}&android_id={self.android_id}&device_unique_id={self.imei_md5}',
                2: '2.1.88.1202.1', 3: 'and_usa', 4: 'en'
            })
            packet = SdpStruct({0: 1, 1: self.sequence, 5: sdp.data}).data
            buf = zstd.compress(packet)
            buf = ((len(buf) + 4) | (16 << 24)).to_bytes(4, 'big') + buf
            self.socket.send(buf)

            while len(self.queue_data) < 4:
                d = self.socket.recv(4096)
                if not d: break
                self.queue_data += d
            if len(self.queue_data) < 4: return None, None
            
            flags = int.from_bytes(self.queue_data[:4], 'big')
            size = flags & 0xFFFFFF
            comp = flags >> 24
            
            while len(self.queue_data) < size:
                d = self.socket.recv(4096)
                if not d: break
                self.queue_data += d
                
            data = self.queue_data[4:size]
            if comp == 16: data = zstd.decompress(data)
            
            res_struct = SdpStruct(data)
            res = res_struct.get(6) or res_struct.get(5)
            if res and isinstance(res, bytes):
                parsed = SdpStruct(res)
                acc_id = parsed.get(0)
                zone_id = parsed[2][0] if 2 in parsed else None
                return acc_id, zone_id
            return None, None
        except:
            return None, None
        finally:
            if self.socket: self.socket.close()

# ── API SKIN & BAN (Dari cekskinamay.py) ─────────────────────────────
def send_info_request(role_id, zone_id, action):
    headers = {"x-api-key": INFO_API_KEY, "Content-Type": "application/json"}
    payload = {"role_id": role_id, "zone_id": zone_id, "type": action}
    try:
        resp = requests.post(INFO_URL, json=payload, headers=headers, timeout=10)
        return resp.json()
    except:
        return {"status": -1}

# ── BACKGROUND WORKER UNTUK PROGRESS REALTIME ───────────────────────
def run_check_task(task_id, mode, lines):
    TASKS[task_id] = {"total": len(lines), "done": 0, "hits": 0, "invalid": 0, "results": [], "status": "running"}
    
    def process_device_login(dev_id):
        bot = GameLogin(dev_id)
        acc_id, zone_id = bot.run()
        if acc_id and zone_id:
            TASKS[task_id]["hits"] += 1
            TASKS[task_id]["results"].append(f"Device id: {dev_id} | account id: {acc_id} | zone id: {zone_id}")
        else:
            TASKS[task_id]["invalid"] += 1
        TASKS[task_id]["done"] += 1

    def process_cekskin(line):
        role_m = re.search(r'account id:\s*(\d+)', line)
        zone_m = re.search(r'zone id:\s*(\d+)', line)
        if role_m and zone_m:
            role_id, zone_id = role_m.group(1), zone_m.group(1)
            res = send_info_request(role_id, zone_id, "lookup")
            if res.get("status") == 0 and res.get("data"):
                TASKS[task_id]["hits"] += 1
                data = res["data"]
                TASKS[task_id]["results"].append(f"ID: {data.get('role_id')} | Name: {data.get('name')} | Skin: {data.get('skin_count')}")
            else:
                TASKS[task_id]["invalid"] += 1
        else:
            TASKS[task_id]["invalid"] += 1
        TASKS[task_id]["done"] += 1

    with ThreadPoolExecutor(max_workers=10) as executor:
        if mode == "device_login":
            executor.map(process_device_login, lines)
        elif mode == "cekskin":
            executor.map(process_cekskin, lines)
            
    TASKS[task_id]["status"] = "completed"

# ── HTML TEMPLATES ───────────────────────────────────────────────────
HTML_BASE = """
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MLBB Tools Web</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; margin: 0; padding: 0; color: #333; }
        .header { background: #4a00e0; padding: 15px; color: white; display: flex; justify-content: space-between; align-items: center; }
        .container { max-width: 900px; margin: 30px auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .btn { padding: 10px 15px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; color: white; display: inline-block; }
        .btn-primary { background: #4a00e0; }
        .btn-success { background: #28a745; }
        .btn-danger { background: #dc3545; }
        .btn-warning { background: #ffc107; color: black; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
        th { background: #f8f9fa; }
        .progress-container { background: #e9ecef; border-radius: 5px; height: 30px; margin: 20px 0; overflow: hidden; }
        .progress-bar { background: #4a00e0; height: 100%; width: 0%; color: white; text-align: center; line-height: 30px; font-weight: bold; transition: width 0.5s; }
        pre { background: #1e1e1e; color: #00ff00; padding: 15px; border-radius: 5px; max-height: 300px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h2>🎮 MLBB Tools Web</h2>
        <div>
            {% if session.get('user') %}
                <span>Hi, {{ session.get('user') }}</span>
                <a href="/logout" class="btn btn-danger">Logout</a>
            {% endif %}
        </div>
    </div>
    <div class="container">
        {% block content %}{% endblock %}
    </div>
</body>
</html>
"""

HTML_LOGIN = HTML_BASE.replace("{% block content %}{% endblock %}", """
    <h3>🔐 Login Member</h3>
    {% if error %}<p style="color:red;">{{ error }}</p>{% endif %}
    <form method="POST">
        <p><input type="text" name="username" placeholder="Username" required></p>
        <p><input type="password" name="password" placeholder="Password" required></p>
        <button type="submit" class="btn btn-primary">Login</button>
    </form>
    <hr>
    <h3>🎟️ Redeem Lisensi Baru</h3>
    {% if msg %}<p style="color:green;">{{ msg }}</p>{% endif %}
    <form method="POST" action="/redeem">
        <p><input type="text" name="username" placeholder="Buat Username Baru" required></p>
        <p><input type="password" name="password" placeholder="Buat Password" required></p>
        <p><input type="text" name="code" placeholder="Masukkan Kode Lisensi (KEY-...)" required></p>
        <button type="submit" class="btn btn-success">Daftar & Aktivasi</button>
    </form>
""")

HTML_DASHBOARD = HTML_BASE.replace("{% block content %}{% endblock %}", """
    <h3>📊 Dashboard</h3>
    {% if role == 'admin' %}
        <div style="background:#ffe; padding:15px; border-radius:8px; margin-bottom:20px;">
            <h4>⚙️ Admin Panel - Generate Lisensi</h4>
            <form method="POST" action="/generate">
                <select name="days">
                    <option value="1">1 Hari</option>
                    <option value="3">3 Hari</option>
                    <option value="7">7 Hari</option>
                    <option value="30">30 Hari</option>
                </select>
                <button type="submit" class="btn btn-warning">Generate Kode</button>
            </form>
            {% if new_code %}<p>Kode Baru: <strong style="color:green; font-size:20px;">{{ new_code }}</strong></p>{% endif %}
            
            <h4>Daftar Kode Aktif</h4>
            <ul>
                {% for c, d in redeems.items() %}
                    <li>{{ c }} ({{ d }} Hari)</li>
                {% endfor %}
            </ul>
        </div>
    {% endif %}

    <h4>🛠️ Tools MLBB</h4>
    <p>Status Lisensi: {% if expiry > now %} <span style="color:green;font-weight:bold;">AKTIF</span> {% else %} <span style="color:red;font-weight:bold;">KADALUARSA</span> {% endif %}</p>
    
    <form method="POST" action="/upload" enctype="multipart/form-data">
        <p>
            <select name="mode">
                <option value="device_login">Device Login Check</option>
                <option value="cekskin">Cek Skin / Lookup</option>
            </select>
        </p>
        <p><input type="file" name="file" accept=".txt" required></p>
        <button type="submit" class="btn btn-primary">Upload & Start</button>
    </form>

    <div id="progress-box" style="display:none;">
        <h3>⏳ Proses Berjalan...</h3>
        <div class="progress-container">
            <div id="progress-bar" class="progress-bar">0%</div>
        </div>
        <p>Done: <span id="done">0</span> / <span id="total">0</span> | Hits: <span id="hits">0</span> | Invalid: <span id="invalid">0</span></p>
        <pre id="results"></pre>
    </div>
    
    <script>
        let taskInterval;
        function startProgress(taskId) {
            document.getElementById('progress-box').style.display = 'block';
            taskInterval = setInterval(() => {
                fetch('/api/progress/' + taskId)
                .then(res => res.json())
                .then(data => {
                    let percent = Math.round((data.done / data.total) * 100);
                    document.getElementById('progress-bar').style.width = percent + '%';
                    document.getElementById('progress-bar').innerText = percent + '%';
                    document.getElementById('done').innerText = data.done;
                    document.getElementById('total').innerText = data.total;
                    document.getElementById('hits').innerText = data.hits;
                    document.getElementById('invalid').innerText = data.invalid;
                    document.getElementById('results').innerText = data.results.join('\\n');
                    
                    if(data.status === 'completed') {
                        clearInterval(taskInterval);
                        document.getElementById('progress-bar').style.background = '#28a745';
                    }
                });
            }, 1000);
        }
    </script>
""")

# ── ROUTES ───────────────────────────────────────────────────────────
@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return render_template_string(HTML_LOGIN, error=None, msg=None)

@app.route("/login", methods=["POST"])
def login():
    db = load_db()
    u = request.form.get("username")
    p = request.form.get("password")
    if u in db["users"] and db["users"][u]["password"] == p:
        session["user"] = u
        return redirect(url_for("dashboard"))
    return render_template_string(HTML_LOGIN, error="Username/Password salah!", msg=None)

@app.route("/redeem", methods=["POST"])
def redeem():
    db = load_db()
    u = request.form.get("username")
    p = request.form.get("password")
    code = request.form.get("code")
    
    if code in db["redeems"]:
        days = db["redeems"][code]
        now = datetime.datetime.now().timestamp()
        expiry = now + (days * 86400)
        db["users"][u] = {"password": p, "role": "member", "expiry": expiry}
        del db["redeems"][code]
        save_db(db)
        return render_template_string(HTML_LOGIN, error=None, msg="Lisensi berhasil diredeem! Silakan login.")
    return render_template_string(HTML_LOGIN, error="Kode lisensi tidak valid!", msg=None)

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("index"))
    db = load_db()
    user = session["user"]
    if user not in db["users"]: return redirect(url_for("index"))
    
    data = db["users"][user]
    role = data.get("role", "member")
    expiry = data.get("expiry", 0)
    now = datetime.datetime.now().timestamp()
    
    new_code = session.pop("new_code", None)
    return render_template_string(HTML_DASHBOARD, role=role, redeems=db["redeems"], expiry=expiry, now=now, new_code=new_code)

@app.route("/generate", methods=["POST"])
def generate():
    if "user" not in session: return redirect(url_for("index"))
    db = load_db()
    if db["users"][session["user"]].get("role") != "admin": return redirect(url_for("dashboard"))
    
    days = int(request.form.get("days"))
    code = f"KEY-{days}D-" + secrets.token_hex(4).upper()
    db["redeems"][code] = days
    save_db(db)
    session["new_code"] = code
    return redirect(url_for("dashboard"))

@app.route("/upload", methods=["POST"])
def upload():
    if "user" not in session: return redirect(url_for("index"))
    db = load_db()
    user = db["users"][session["user"]]
    
    # Cek lisensi member
    if user.get("role") == "member" and user.get("expiry", 0) < datetime.datetime.now().timestamp():
        return "Lisensi Kadaluarsa!", 403

    mode = request.form.get("mode")
    file = request.files["file"]
    lines = [line.strip() for line in file.read().decode('utf-8', errors='ignore').split('\n') if line.strip()]
    
    task_id = secrets.token_hex(8)
    
    # Jalankan di background thread agar web tidak crash/hang
    thread = threading.Thread(target=run_check_task, args=(task_id, mode, lines))
    thread.start()
    
    return render_template_string(HTML_DASHBOARD + "<script>startProgress('" + task_id + "');</script>", 
                                  role=user.get("role"), redeems=db["redeems"], expiry=user.get("expiry",0), now=datetime.datetime.now().timestamp(), new_code=None)

@app.route("/api/progress/<task_id>")
def api_progress(task_id):
    if "user" not in session: return jsonify({"error": "unauth"}), 403
    task = TASKS.get(task_id)
    if not task: return jsonify({"error": "not found"}), 404
    return jsonify(task)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    # Buat db awal jika tidak ada
    if not os.path.exists(DATA_FILE):
        save_db({"users": {ADMIN_USERNAME: {"password": ADMIN_PASSWORD, "role": "admin", "expiry": 9999999999}}, "redeems": {}})
    app.run(host="0.0.0.0", port=5000, debug=True)
