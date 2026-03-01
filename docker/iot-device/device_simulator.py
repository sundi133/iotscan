#!/usr/bin/env python3
"""
Simulated Vulnerable IoT Smart Camera

A deliberately vulnerable IoT device simulator for security testing.
Exposes multiple services with common IoT security weaknesses:

- HTTP (port 80):  Insecure web admin panel
- Telnet (port 23): Default credentials
- FTP (port 21):   Anonymous access
- CoAP (port 5683): Unauthenticated resource access
- MQTT client:      Publishes telemetry to broker

DO NOT deploy this in production. For testing only.
"""

import json
import os
import random
import socketserver
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

# ─── Configuration ────────────────────────────────────────────────

DEVICE_INFO = {
    "model": "SmartCam Pro X200",
    "manufacturer": "IoTCorp",
    "firmware_version": "1.2.3",
    "hardware_version": "HW-REV-B",
    "serial": "IOTC-2024-00042",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "uptime_seconds": 0,
}

DEFAULT_CREDENTIALS = {
    "admin": "admin",
    "root": "root",
    "user": "1234",
}

WIFI_CONFIG = {
    "ssid": "IoTCorpNetwork",
    "password": "SuperSecret123!",
    "security": "WPA2",
    "channel": 6,
}

DEVICE_CONFIG = {
    "wifi": WIFI_CONFIG,
    "api_key": "sk-iotcorp-a1b2c3d4e5f6g7h8i9j0",
    "cloud_endpoint": "http://api.iotcorp.example.com/v1/telemetry",
    "mqtt_broker": "mqtt-broker",
    "mqtt_port": 1883,
    "telnet_enabled": True,
    "ftp_enabled": True,
    "debug_mode": True,
    "auto_update": True,
    "update_server": "http://firmware.iotcorp.example.com/updates",
    "signing_method": "none",
    "db_password": "postgres_iot_2024",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAH...FAKE_KEY...==\n-----END RSA PRIVATE KEY-----",
}

ENV_SECRETS = """# IoTCorp SmartCam Configuration
DB_HOST=db.internal.iotcorp.example.com
DB_PASSWORD=postgres_iot_2024
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
CLOUD_API_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.FAKE
MQTT_PASSWORD=mosquitto_default
STRIPE_SECRET_KEY=FAKE_STRIPE_KEY_FOR_TESTING_ONLY
"""

# Simulated firmware binary with intentionally detectable patterns
FIRMWARE_HEADER = (
    b"\x68\x73\x71\x73"  # SquashFS magic
    + b"\x00" * 28
    + b"\x7fELF"  # ELF magic
    + b"\x00" * 28
    + b'password = "admin123"\n'
    + b'api_key = "AKIAIOSFODNN7EXAMPLE1234"\n'
    + b"strcpy(buf, user_input);\n"
    + b"gets(line_buffer);\n"
    + b"sprintf(msg, user_fmt);\n"
    + b"BusyBox v1.30.1 (2023-01-15)\n"
    + b"OpenSSL 1.0.1e\n"
    + b"dropbear_2019.78\n"
    + b"DES_ecb_encrypt\n"
    + b"MD5_Init\n"
    + b"RC4\n"
    + b"srand(time(NULL))\n"
    + b"telnetd -l /bin/sh\n"
    + b"DEBUG=1\n"
    + b"JTAG_EN=true\n"
    + b"/home/developer/build/smartcam\n"
)
FIRMWARE_BIN = FIRMWARE_HEADER + b"\x00" * (4096 - len(FIRMWARE_HEADER))

start_time = time.time()


# ─── HTTP Server (port 80) ───────────────────────────────────────

class IoTWebHandler(BaseHTTPRequestHandler):
    """Intentionally vulnerable web interface for a smart camera."""

    server_version = "GoAhead-Webs/2.5.0"

    def do_GET(self):
        DEVICE_INFO["uptime_seconds"] = int(time.time() - start_time)

        routes = {
            "/": self._index,
            "/admin": self._admin,
            "/config.json": self._config_json,
            "/config.yaml": self._config_yaml,
            "/config.xml": self._config_xml,
            "/.env": self._env,
            "/debug": self._debug,
            "/firmware.bin": self._firmware,
            "/syslog": self._syslog,
            "/phpinfo.php": self._phpinfo,
            "/console": self._console,
            "/diag.html": self._diag,
            "/goform/system": self._goform,
            "/HNAP1/": self._hnap,
            "/backup.tar.gz": self._backup_stub,
            "/setup": self._setup,
            "/api/v1/device": self._api_device,
            "/api/v1/stream": self._api_stream,
            "/cgi-bin/status": self._cgi_status,
        }

        handler = routes.get(self.path)
        if handler:
            handler()
        elif self.path.startswith("/goform/"):
            self._goform()
        else:
            self._not_found()

    def do_POST(self):
        # Accept POST on goform and API endpoints without auth
        if self.path.startswith("/goform/") or self.path.startswith("/api/"):
            content_length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(content_length)
            self._json_response(200, {"status": "ok", "message": "Command accepted"})
        else:
            self._not_found()

    def do_PUT(self):
        self._json_response(200, {"status": "ok"})

    def do_DELETE(self):
        self._json_response(200, {"status": "deleted"})

    def do_TRACE(self):
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        self.end_headers()
        self.wfile.write(b"TRACE / HTTP/1.1\r\n")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS, TRACE")
        origin = self.headers.get("Origin", "*")
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, TRACE")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()

    # ── Route handlers ──

    def _send_insecure_headers(self):
        """Deliberately omit all security headers."""
        self.send_header("Server", "GoAhead-Webs/2.5.0")
        self.send_header("Access-Control-Allow-Origin", "*")
        # No X-Frame-Options
        # No Content-Security-Policy
        # No Strict-Transport-Security
        # No X-Content-Type-Options
        # No X-XSS-Protection

    def _index(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self._send_insecure_headers()
        self.end_headers()
        html = f"""<!DOCTYPE html>
<html>
<head><title>{DEVICE_INFO['model']} - Admin Panel</title></head>
<body>
<h1>{DEVICE_INFO['model']}</h1>
<p>Firmware: {DEVICE_INFO['firmware_version']}</p>
<p>Serial: {DEVICE_INFO['serial']}</p>
<p>MAC: {DEVICE_INFO['mac_address']}</p>
<p>Uptime: {DEVICE_INFO['uptime_seconds']}s</p>
<ul>
  <li><a href="/admin">Admin Panel</a></li>
  <li><a href="/setup">Setup Wizard</a></li>
  <li><a href="/debug">Debug Console</a></li>
  <li><a href="/diag.html">Diagnostics</a></li>
</ul>
</body></html>"""
        self.wfile.write(html.encode())

    def _admin(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self._send_insecure_headers()
        self.end_headers()
        html = f"""<!DOCTYPE html>
<html><head><title>Admin - {DEVICE_INFO['model']}</title></head>
<body>
<h1>Administration Panel</h1>
<p>Welcome, admin. No authentication required.</p>
<form action="/goform/system" method="POST">
  <h3>System Settings</h3>
  <label>Hostname: <input name="hostname" value="smartcam-{DEVICE_INFO['serial']}"></label><br>
  <label>WiFi SSID: <input name="ssid" value="{WIFI_CONFIG['ssid']}"></label><br>
  <label>WiFi Password: <input name="wifi_pass" type="text" value="{WIFI_CONFIG['password']}"></label><br>
  <label>Cloud API Key: <input name="api_key" value="{DEVICE_CONFIG['api_key']}"></label><br>
  <button type="submit">Save</button>
</form>
<h3>Firmware Update</h3>
<form action="/goform/firmware_upload" method="POST" enctype="multipart/form-data">
  <input type="file" name="firmware"><button type="submit">Upload</button>
</form>
<h3>Execute Command</h3>
<form action="/goform/exec" method="POST">
  <input name="cmd" placeholder="ping 8.8.8.8"><button type="submit">Run</button>
</form>
</body></html>"""
        self.wfile.write(html.encode())

    def _config_json(self):
        self._json_response(200, DEVICE_CONFIG)

    def _config_yaml(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/yaml")
        self._send_insecure_headers()
        self.end_headers()
        yaml_content = f"""# SmartCam Pro X200 Configuration
wifi:
  ssid: "{WIFI_CONFIG['ssid']}"
  password: "{WIFI_CONFIG['password']}"
api_key: "{DEVICE_CONFIG['api_key']}"
cloud_endpoint: "{DEVICE_CONFIG['cloud_endpoint']}"
db_password: "{DEVICE_CONFIG['db_password']}"
"""
        self.wfile.write(yaml_content.encode())

    def _config_xml(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self._send_insecure_headers()
        self.end_headers()
        xml = f"""<?xml version="1.0"?>
<config>
  <wifi ssid="{WIFI_CONFIG['ssid']}" password="{WIFI_CONFIG['password']}"/>
  <cloud api_key="{DEVICE_CONFIG['api_key']}" endpoint="{DEVICE_CONFIG['cloud_endpoint']}"/>
</config>"""
        self.wfile.write(xml.encode())

    def _env(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self._send_insecure_headers()
        self.end_headers()
        self.wfile.write(ENV_SECRETS.encode())

    def _debug(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self._send_insecure_headers()
        self.end_headers()
        debug_info = f"""=== Debug Console ===
Device: {DEVICE_INFO['model']}
Firmware: {DEVICE_INFO['firmware_version']}
Build: /home/developer/build/smartcam_v{DEVICE_INFO['firmware_version']}
Uptime: {DEVICE_INFO['uptime_seconds']}s
Free RAM: {random.randint(8000, 16000)}KB
CPU Temp: {random.randint(45, 65)}C
WiFi SSID: {WIFI_CONFIG['ssid']}
WiFi Signal: -{random.randint(30, 70)}dBm
MQTT Connected: true
MQTT Broker: {DEVICE_CONFIG['mqtt_broker']}:{DEVICE_CONFIG['mqtt_port']}
Telnet: enabled
FTP: enabled
JTAG: enabled
UART: /dev/ttyS0 115200
Last crash: segfault in libcurl.so.4
Stack: 0x7fff5fbff000
"""
        self.wfile.write(debug_info.encode())

    def _firmware(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", "attachment; filename=firmware.bin")
        self._send_insecure_headers()
        self.end_headers()
        self.wfile.write(FIRMWARE_BIN)

    def _syslog(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self._send_insecure_headers()
        self.end_headers()
        logs = f"""Jan  1 00:00:01 smartcam syslogd started
Jan  1 00:00:02 smartcam kernel: Linux version 4.14.0 (root@buildserver)
Jan  1 00:00:02 smartcam kernel: JTAG interface enabled
Jan  1 00:00:03 smartcam dropbear[100]: Running in background
Jan  1 00:00:03 smartcam telnetd[101]: listening on 0.0.0.0:23
Jan  1 00:00:04 smartcam ftpd[102]: accepting connections on port 21
Jan  1 00:00:05 smartcam httpd[103]: GoAhead-Webs/2.5.0 started on port 80
Jan  1 00:00:06 smartcam mqtt[104]: connected to {DEVICE_CONFIG['mqtt_broker']}:{DEVICE_CONFIG['mqtt_port']}
Jan  1 00:00:10 smartcam auth[200]: login admin from 192.168.1.50 - password 'admin' - SUCCESS
Jan  1 00:00:15 smartcam camera[300]: stream started rtsp://0.0.0.0:554/live
"""
        self.wfile.write(logs.encode())

    def _phpinfo(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self._send_insecure_headers()
        self.end_headers()
        self.wfile.write(b"<h1>PHP Info - Not Available</h1><p>GoAhead embedded server</p>")

    def _console(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self._send_insecure_headers()
        self.end_headers()
        self.wfile.write(b"<h1>Debug Console</h1><pre>root@smartcam:~# </pre>")

    def _diag(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self._send_insecure_headers()
        self.end_headers()
        html = """<html><head><title>Diagnostics</title></head><body>
<h1>Network Diagnostics</h1>
<form action="/goform/diag" method="POST">
  <label>Ping host: <input name="host" value="8.8.8.8"></label>
  <button type="submit">Run</button>
</form>
</body></html>"""
        self.wfile.write(html.encode())

    def _goform(self):
        self._json_response(200, {"status": "ok", "goahead": True})

    def _hnap(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self._send_insecure_headers()
        self.end_headers()
        xml = f"""<?xml version="1.0" encoding="utf-8"?>
<HNAP1>
  <DeviceName>{DEVICE_INFO['model']}</DeviceName>
  <FirmwareVersion>{DEVICE_INFO['firmware_version']}</FirmwareVersion>
  <ModelName>X200</ModelName>
  <VendorName>IoTCorp</VendorName>
</HNAP1>"""
        self.wfile.write(xml.encode())

    def _backup_stub(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/gzip")
        self._send_insecure_headers()
        self.end_headers()
        # Fake gzip header
        self.wfile.write(b"\x1f\x8b\x08\x00" + b"\x00" * 128)

    def _setup(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self._send_insecure_headers()
        self.end_headers()
        self.wfile.write(b"<h1>Setup Wizard</h1><p>No authentication required.</p>")

    def _api_device(self):
        self._json_response(200, {
            "device": DEVICE_INFO,
            "network": {"ip": "192.168.1.100", "gateway": "192.168.1.1"},
            "services": {"telnet": True, "ftp": True, "ssh": False, "rtsp": True},
        })

    def _api_stream(self):
        self._json_response(200, {
            "rtsp_url": "rtsp://admin:admin@192.168.1.100:554/live",
            "snapshot_url": "http://192.168.1.100/snapshot.jpg",
            "resolution": "1920x1080",
            "encoding": "H.264",
        })

    def _cgi_status(self):
        self._json_response(200, {"uptime": DEVICE_INFO["uptime_seconds"], "load": 0.42})

    def _not_found(self):
        self.send_response(404)
        self.send_header("Server", "GoAhead-Webs/2.5.0")
        self.end_headers()
        self.wfile.write(b"404 - Not Found")

    def _json_response(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._send_insecure_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def log_message(self, format, *args):
        # Minimal logging
        pass


# ─── Telnet Server (port 23) ─────────────────────────────────────

class TelnetHandler(socketserver.BaseRequestHandler):
    """Simulated telnet service with default credentials and version banner."""

    BANNER = (
        f"\r\n"
        f"===========================================\r\n"
        f"  {DEVICE_INFO['model']}\r\n"
        f"  Firmware {DEVICE_INFO['firmware_version']}\r\n"
        f"  {DEVICE_INFO['manufacturer']}\r\n"
        f"  BusyBox v1.30.1 built-in shell\r\n"
        f"===========================================\r\n"
        f"\r\n"
    )

    def handle(self):
        try:
            self.request.settimeout(30)
            self.request.sendall(self.BANNER.encode())
            self.request.sendall(b"login: ")
            username = self._readline()
            self.request.sendall(b"password: ")
            password = self._readline()

            if DEFAULT_CREDENTIALS.get(username) == password:
                self.request.sendall(b"\r\nLogin successful.\r\n")
                self.request.sendall(f"root@smartcam:~# ".encode())
                # Keep connection open briefly then close
                try:
                    self.request.settimeout(5)
                    self.request.recv(1024)
                except Exception:
                    pass
            else:
                self.request.sendall(b"\r\nLogin incorrect.\r\n")
        except Exception:
            pass

    def _readline(self):
        data = b""
        try:
            while True:
                byte = self.request.recv(1)
                if not byte or byte in (b"\n", b"\r"):
                    break
                data += byte
        except Exception:
            pass
        return data.decode("utf-8", errors="ignore").strip()


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ─── FTP Server (port 21) ────────────────────────────────────────

class FTPHandler(socketserver.BaseRequestHandler):
    """Simulated FTP service with anonymous access and banner disclosure."""

    BANNER = f"220 {DEVICE_INFO['model']} FTP server (vsftpd 2.3.4) ready.\r\n"

    def handle(self):
        try:
            self.request.settimeout(30)
            self.request.sendall(self.BANNER.encode())

            while True:
                self.request.settimeout(10)
                data = self.request.recv(1024)
                if not data:
                    break
                cmd = data.decode("utf-8", errors="ignore").strip().upper()

                if cmd.startswith("USER"):
                    user = cmd[5:].strip() if len(cmd) > 5 else ""
                    if user.lower() in ("anonymous", "ftp"):
                        self.request.sendall(b"230 Anonymous login ok.\r\n")
                    else:
                        self.request.sendall(b"331 Password required.\r\n")
                elif cmd.startswith("PASS"):
                    self.request.sendall(b"230 Login successful.\r\n")
                elif cmd.startswith("SYST"):
                    self.request.sendall(b"215 UNIX Type: L8\r\n")
                elif cmd.startswith("FEAT"):
                    self.request.sendall(b"211-Features:\r\n UTF8\r\n211 End\r\n")
                elif cmd.startswith("PWD"):
                    self.request.sendall(b'257 "/" is the current directory\r\n')
                elif cmd.startswith("LIST"):
                    self.request.sendall(b"150 Opening data connection.\r\n")
                    self.request.sendall(b"226 Transfer complete.\r\n")
                elif cmd.startswith("QUIT"):
                    self.request.sendall(b"221 Goodbye.\r\n")
                    break
                else:
                    self.request.sendall(b"502 Command not implemented.\r\n")
        except Exception:
            pass


# ─── CoAP Server (port 5683) ─────────────────────────────────────

class CoAPServer:
    """Minimal CoAP server responding to resource discovery."""

    def __init__(self, port=5683):
        self.port = port

    def run(self):
        import socket as _socket

        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.port))
        print(f"[CoAP] Listening on UDP :{self.port}")

        while True:
            try:
                data, addr = sock.recvfrom(1024)
                if len(data) < 4:
                    continue
                # Parse minimal CoAP header
                ver_type_tkl = data[0]
                code = data[1]
                msg_id = struct.unpack("!H", data[2:4])[0]
                tkl = ver_type_tkl & 0x0F
                token = data[4 : 4 + tkl] if tkl > 0 else b""

                # Build ACK response
                if code == 1:  # GET
                    payload = (
                        b'</device>;rt="iot.device";ct=0,'
                        b'</temperature>;rt="sensor";ct=0,'
                        b'</firmware>;rt="iot.firmware";ct=0,'
                        b'</config>;rt="iot.config";ct=0'
                    )
                    # CoAP header: Ver=1, Type=ACK(2), TKL, Code=2.05 Content(69)
                    resp = bytes([0x60 | tkl, 69]) + struct.pack("!H", msg_id) + token
                    # Content-Format option (12) = text/plain (0)
                    resp += b"\xc0"  # Option delta=12, length=0
                    resp += b"\xff"  # Payload marker
                    resp += payload
                    sock.sendto(resp, addr)
            except Exception:
                continue


# ─── SNMP Responder (port 161) ────────────────────────────────────

class SNMPResponder:
    """Minimal SNMP responder that accepts default community strings."""

    ACCEPTED_COMMUNITIES = {"public", "private", "community", "admin", "default"}

    def __init__(self, port=161):
        self.port = port

    def run(self):
        import socket as _socket

        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.port))
        print(f"[SNMP] Listening on UDP :{self.port}")

        while True:
            try:
                data, addr = sock.recvfrom(4096)
                # Very basic SNMP v1/v2c community string extraction
                community = self._extract_community(data)
                if community and community in self.ACCEPTED_COMMUNITIES:
                    # Send a minimal GetResponse with sysDescr
                    resp = self._build_response(data)
                    sock.sendto(resp, addr)
            except Exception:
                continue

    def _extract_community(self, data):
        """Extract community string from SNMP packet (basic BER parsing)."""
        try:
            idx = 0
            if data[idx] != 0x30:  # SEQUENCE
                return None
            idx += 1
            # Skip length
            if data[idx] & 0x80:
                num_bytes = data[idx] & 0x7F
                idx += 1 + num_bytes
            else:
                idx += 1
            # Version (INTEGER)
            if data[idx] != 0x02:
                return None
            idx += 1
            vlen = data[idx]
            idx += 1 + vlen
            # Community (OCTET STRING)
            if data[idx] != 0x04:
                return None
            idx += 1
            clen = data[idx]
            idx += 1
            return data[idx : idx + clen].decode("utf-8", errors="ignore")
        except (IndexError, UnicodeDecodeError):
            return None

    def _build_response(self, request):
        """Build minimal SNMP GetResponse."""
        sys_descr = f"{DEVICE_INFO['model']} {DEVICE_INFO['firmware_version']}".encode()
        # Minimal well-formed SNMP response
        # This is a simplified response - enough for iotscan to detect
        try:
            # Copy most of the request but change PDU type to GetResponse (0xA2)
            resp = bytearray(request)
            # Find the PDU type byte (0xA0 for GetRequest) and change to 0xA2
            for i in range(len(resp)):
                if resp[i] == 0xA0:
                    resp[i] = 0xA2
                    break
            return bytes(resp)
        except Exception:
            return request


# ─── MQTT Telemetry Publisher ─────────────────────────────────────

def mqtt_publisher():
    """Publish simulated sensor data to MQTT broker."""
    broker = os.environ.get("MQTT_BROKER", "mqtt-broker")
    port = int(os.environ.get("MQTT_PORT", "1883"))

    try:
        import paho.mqtt.client as mqtt_client
    except ImportError:
        print("[MQTT] paho-mqtt not installed, skipping telemetry publishing")
        return

    client = mqtt_client.Client(client_id=f"smartcam-{DEVICE_INFO['serial']}")

    def on_connect(client, userdata, flags, rc, properties=None):
        print(f"[MQTT] Connected to broker {broker}:{port}")
        # Publish device announcement
        client.publish(
            "iot/devices/smartcam/status",
            json.dumps({"online": True, **DEVICE_INFO}),
            retain=True,
        )

    client.on_connect = on_connect

    while True:
        try:
            client.connect(broker, port, keepalive=60)
            client.loop_start()
            break
        except Exception as e:
            print(f"[MQTT] Waiting for broker... ({e})")
            time.sleep(5)

    # Publish telemetry periodically
    while True:
        try:
            telemetry = {
                "temperature": round(random.uniform(20.0, 35.0), 1),
                "humidity": round(random.uniform(30.0, 80.0), 1),
                "motion_detected": random.choice([True, False]),
                "cpu_temp": round(random.uniform(45.0, 65.0), 1),
                "uptime": int(time.time() - start_time),
            }
            client.publish("iot/devices/smartcam/telemetry", json.dumps(telemetry))
            client.publish(
                "iot/devices/smartcam/config",
                json.dumps({"wifi_ssid": WIFI_CONFIG["ssid"], "api_key": DEVICE_CONFIG["api_key"]}),
            )
        except Exception:
            pass
        time.sleep(10)


# ─── Main ─────────────────────────────────────────────────────────

def main():
    print(f"Starting {DEVICE_INFO['model']} Simulator...")
    print("=" * 50)
    print("WARNING: This is a deliberately vulnerable device.")
    print("For security testing purposes only.")
    print("=" * 50)

    threads = []

    # HTTP Server (port 80)
    http_server = HTTPServer(("0.0.0.0", 80), IoTWebHandler)
    t = threading.Thread(target=http_server.serve_forever, daemon=True)
    t.start()
    threads.append(t)
    print("[HTTP]   Listening on :80")

    # Telnet Server (port 23)
    telnet_server = ThreadedTCPServer(("0.0.0.0", 23), TelnetHandler)
    t = threading.Thread(target=telnet_server.serve_forever, daemon=True)
    t.start()
    threads.append(t)
    print("[Telnet] Listening on :23")

    # FTP Server (port 21)
    ftp_server = ThreadedTCPServer(("0.0.0.0", 21), FTPHandler)
    t = threading.Thread(target=ftp_server.serve_forever, daemon=True)
    t.start()
    threads.append(t)
    print("[FTP]    Listening on :21")

    # CoAP Server (port 5683)
    coap = CoAPServer(5683)
    t = threading.Thread(target=coap.run, daemon=True)
    t.start()
    threads.append(t)

    # SNMP Responder (port 161)
    snmp = SNMPResponder(161)
    t = threading.Thread(target=snmp.run, daemon=True)
    t.start()
    threads.append(t)

    # MQTT Telemetry Publisher
    t = threading.Thread(target=mqtt_publisher, daemon=True)
    t.start()
    threads.append(t)

    print()
    print("All services running. Waiting for connections...")
    print()

    # Keep main thread alive
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\nShutting down...")


if __name__ == "__main__":
    main()
