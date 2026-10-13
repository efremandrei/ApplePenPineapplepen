#!/usr/bin/env python3
"""Exercise the shipped APK on a disposable emulator and an owned HTTP fixture."""
import http.server
import json
import pathlib
import re
import subprocess
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
    adb("shell", "input", "keyevent", "KEYCODE_MOVE_END")
    adb("shell", "input", "keyevent", "--longpress", "KEYCODE_DEL")
    # Inputs used here are initially empty, except the TCP selection handled below.
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


fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 8089), Fixture)
threading.Thread(target=fixture.serve_forever, daemon=True).start()
try:
    adb("install", "-r", str(ROOT / "downloads/ApplePen-v0.1.0.apk"))
    adb("install", "-r", str(ROOT / "downloads/ApplePen-v0.2.0.apk"))
    adb("shell", "pm", "grant", PACKAGE, "android.permission.POST_NOTIFICATIONS")
    adb("shell", "am", "start", "-W", "-n", PACKAGE + "/.MainActivity")
    find(lambda n: n.get("text") == "APPLEPEN")
    fill("Destination IP", "10.0.2.2")
    tap(find(lambda n: n.get("class") == "android.widget.Spinner", scroll=True))
    click("Custom ports")
    field = find(lambda n: n.get("content-desc") == "TCP ports", scroll=True)
    tap(field)
    # Select all through the observed editor rather than relying on repeated delete counts.
    adb("shell", "input", "keycombination", "113", "29")  # Ctrl+A
    adb("shell", "input", "text", "8089")
    adb("shell", "input", "keyevent", "KEYCODE_BACK")
    fill("Additional HTTP ports", "8089")
    click("I own this target or have permission to assess it.", scroll=True)
    click("Start assessment", scroll=True)
    find(lambda n: "1 open ports" in n.get("text", ""), attempts=25)
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
            assert report["services"][0]["service"] == "HTTP"
            assert report["configuration"]["lookupCves"] is False
            assert report["counts"]["open"] == 1
    click("History")
    find(lambda n: n.get("text") == "10.0.2.2")
    click("Rescan this target", scroll=True)
    find(lambda n: n.get("content-desc") == "Destination IP" and n.get("text") == "10.0.2.2")
    print("Emulator smoke passed: signed upgrade, form, foreground scan, history, rescan, PDF/HTML/JSON exports.", flush=True)
finally:
    fixture.shutdown()
    (OUT / "logcat.txt").write_bytes(adb("logcat", "-d", "-t", "1500"))
