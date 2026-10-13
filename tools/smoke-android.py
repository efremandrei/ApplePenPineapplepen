#!/usr/bin/env python3
"""Exercise the shipped APK on a disposable emulator and an owned HTTP fixture."""
import http.server
import json
import pathlib
import re
import subprocess
import socketserver
import ssl
import tempfile
import threading
import time
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "app/build/smoke"
OUT.mkdir(parents=True, exist_ok=True)
PACKAGE = "info.hen14.applepen"


def adb(*args):
    return subprocess.check_output(["adb", *args], timeout=30)


def snapshot():
    adb("shell", "uiautomator", "dump", "/sdcard/applepen-ui.xml")
    data = adb("shell", "cat", "/sdcard/applepen-ui.xml")
    (OUT / "last-ui.xml").write_bytes(data)
    return ET.fromstring(data)


def find(selector, scroll=False, attempts=12):
    for _ in range(attempts):
        nodes = list(snapshot().iter("node"))
        for node in nodes:
            if selector(node) and node.get("enabled") != "false":
                return node
        if scroll:
            size = adb("shell", "wm", "size").decode()
            width, height = map(int, re.findall(r"(\d+)x(\d+)", size)[-1])
            adb("shell", "input", "swipe", str(width // 2), str(height * 4 // 5), str(width // 2), str(height // 3), "300")
        time.sleep(0.5)
    raise AssertionError("UI element not found; see last-ui.xml")


def tap(node):
    x1, y1, x2, y2 = map(int, re.findall(r"\d+", node.get("bounds", "")))
    adb("shell", "input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2))
    time.sleep(0.3)


def click(text, scroll=False):
    tap(find(lambda n: n.get("text", "").lower() == text.lower() or n.get("content-desc", "").lower() == text.lower(), scroll))


def fill(label, value):
    tap(find(lambda n: n.get("content-desc") == label, scroll=True))
    adb("shell", "input", "keycombination", "113", "29")  # Ctrl+A
    adb("shell", "input", "text", value)
    adb("shell", "input", "keyevent", "KEYCODE_BACK")


class Fixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><title>ApplePen smoke fixture</title><body>Owned CI fixture</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class RedisFixture(socketserver.BaseRequestHandler):
    def handle(self):
        stream = self.request.makefile("rb")
        if not stream.readline():
            return
        assert stream.readline() == b"$4\r\n" and stream.readline() == b"PING\r\n"
        self.request.sendall(b"+PONG\r\n")
        assert [stream.readline() for _ in range(5)] == [b"*2\r\n", b"$4\r\n", b"INFO\r\n", b"$6\r\n", b"server\r\n"]
        body = b"# Server\r\nredis_version:7.4.1\r\nconfig_file:private-fixture-path\r\n"
        self.request.sendall(b"$" + str(len(body)).encode() + b"\r\n" + body + b"\r\n")


class PostgresFixture(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.makefile("rb").read(8)
        if data:
            assert data == bytes([0, 0, 0, 8, 4, 210, 22, 47])
            self.request.sendall(b"N")


class SmtpFixture(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(b"220 owned fixture ESMTP\r\n")
            line = self.request.makefile("rb").readline()
            if line:
                assert line == b"EHLO applepen.invalid\r\n"
                self.request.sendall(b"250 owned fixture\r\n")
        except (ConnectionResetError, BrokenPipeError):
            pass


class SecureFixture(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with tls_context.wrap_socket(self.request, server_side=True) as connection:
                reader = connection.makefile("rb")
                first = reader.readline()
                if not first:
                    return
                headers = []
                while True:
                    line = reader.readline()
                    if line in (b"\r\n", b""):
                        break
                    headers.append(line)
                credential_requests.extend(line for line in headers if line.lower().startswith(b"authorization:"))
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
            pass


class TcpFixture(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 8089), Fixture)
servers = [fixture, TcpFixture(("127.0.0.1", 16379), RedisFixture), TcpFixture(("127.0.0.1", 15432), PostgresFixture), TcpFixture(("127.0.0.1", 1587), SmtpFixture), TcpFixture(("127.0.0.1", 9443), SecureFixture)]
credential_requests = []
tls_temp = tempfile.TemporaryDirectory(prefix="applepen-smoke-tls-")
cert = pathlib.Path(tls_temp.name) / "cert.pem"
key = pathlib.Path(tls_temp.name) / "key.pem"
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:10.0.2.2"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls_context.load_cert_chain(cert, key)
for server in servers:
    threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    # Seed a real v0.2 report, then verify that the signed v0.3 update keeps it.
    adb("install", "-r", str(ROOT / "downloads/ApplePen-v0.2.0.apk"))
    adb("shell", "pm", "grant", PACKAGE, "android.permission.POST_NOTIFICATIONS")
    adb("shell", "am", "start", "-W", "-n", PACKAGE + "/.MainActivity")
    find(lambda n: n.get("text") == "APPLEPEN")
    fill("Destination IP", "10.0.2.2")
    tap(find(lambda n: n.get("class") == "android.widget.Spinner", scroll=True))
    click("Custom ports")
    fill("TCP ports", "8089")
    fill("Additional HTTP ports", "8089")
    click("I own this target or have permission to assess it.", scroll=True)
    click("Start assessment", scroll=True)
    find(lambda n: "1 open ports" in n.get("text", ""), attempts=25)
    adb("install", "-r", str(ROOT / "downloads/ApplePen-v0.3.0.apk"))
    adb("shell", "am", "start", "-W", "-n", PACKAGE + "/.MainActivity")
    click("History")
    find(lambda n: n.get("text") == "10.0.2.2")
    click("Rescan this target", scroll=True)
    fill("TCP ports", "8089,9443,15432,1587,16379")
    fill("Additional HTTPS ports", "9443")
    # Rescan restores v0.2 scope with new protocol probes off, then enable them explicitly.
    click("Check Redis, PostgreSQL and SMTP", scroll=True)
    fill("Additional Redis ports", "16379")
    fill("Additional PostgreSQL ports", "15432")
    click("Probe TLS 1.0, 1.1, 1.2 and 1.3", scroll=True)
    tap(find(lambda n: n.get("content-desc") == "Authentication method", scroll=True))
    click("Bearer")
    fill("Authentication HTTPS port", "9443")
    fill("Password or Bearer token", "fake-smoke-token")
    click("I own this target or have permission to assess it.", scroll=True)
    click("Start assessment", scroll=True)
    find(lambda n: "5 open ports" in n.get("text", ""), attempts=40)
    (OUT / "report.png").write_bytes(adb("exec-out", "screencap", "-p"))
    # Exercise the native document picker and all three exporter paths.
    for format_, signature in [("PDF", b"%PDF-"), ("HTML", b"<!doctype html>"), ("JSON", b"{")]:
        click(format_)
        save = find(lambda n: n.get("text", "").lower() == "save" or n.get("content-desc", "").lower() == "save", attempts=12)
        tap(save)
        time.sleep(1)
        find(lambda n: n.get("text") == "APPLEPEN")
        names = adb("shell", "find", "/sdcard/Download", "-name", "ApplePen-*." + format_.lower()).decode().splitlines()
        if not names:
            raise AssertionError("Export not found in Downloads")
        destination = OUT / ("report." + format_.lower())
        adb("pull", names[-1], str(destination))
        assert destination.read_bytes().startswith(signature)
        if format_ == "JSON":
            report = json.loads(destination.read_text())
            assert report["targetIp"] == "10.0.2.2"
            services = {s["port"]: s["service"] for s in report["services"]}
            assert services == {1587: "SMTP-compatible", 8089: "HTTP", 9443: "HTTPS", 15432: "PostgreSQL-compatible", 16379: "Redis-compatible"}
            assert report["configuration"]["lookupCves"] is False
            assert report["counts"]["open"] == 5
            assert report["schemaVersion"] == 3
            assert report["configuration"]["authMethod"] == "Bearer"
            assert any("blocked before sending Authorization" in line for line in report["coverage"])
            assert any("TLSv1.2 accepted" in line for line in report["coverage"])
            assert "fake-smoke-token" not in destination.read_text()
            assert "private-fixture-path" not in destination.read_text()
            assert not credential_requests, "Untrusted fixture received Authorization"
    click("History")
    find(lambda n: n.get("text") == "10.0.2.2")
    click("Rescan this target", scroll=True)
    find(lambda n: n.get("content-desc") == "Destination IP" and n.get("text") == "10.0.2.2")
    fill("Additional Redis ports", "16379")
    tap(find(lambda n: n.get("content-desc") == "Authentication method", scroll=True))
    click("None")
    find(lambda n: n.get("content-desc") == "Password or Bearer token" and n.get("text") in ("", "Used for this assessment only"), scroll=True)
    print("Emulator smoke passed: signed upgrade with retained history, protocol scans, TLS probes, blocked untrusted authentication, cleared credentials, rescan, PDF/HTML/JSON exports.", flush=True)
finally:
    for server in servers:
        server.shutdown()
        server.server_close()
    tls_temp.cleanup()
    (OUT / "logcat.txt").write_bytes(adb("logcat", "-d", "-t", "1500"))
