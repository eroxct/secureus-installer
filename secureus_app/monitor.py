"""
SecureUS Network Monitor — Desktop App
Scans your network, flags threats, watches for unknown devices,
and exports a CSV you can upload to SecureUS for a full report.

Entry point: secureus-monitor
"""

import sys, os, csv, socket, struct, threading, time, ipaddress
import subprocess, platform
from datetime import datetime
from collections import defaultdict


def main():
    """Launched by the 'secureus-monitor' console script."""
    try:
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtGui import QColor, QPalette
    except ImportError:
        print(
            "\n  SecureUS Monitor requires PyQt5.\n"
            "  Install it with:\n\n"
            "    pip install secureus[desktop]\n\n"
            "  or:\n\n"
            "    pip install PyQt5\n"
        )
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName("SecureUS Network Monitor")
    app.setStyle("Fusion")

    C = _COLORS()
    palette = QPalette()
    palette.setColor(QPalette.Window,          QColor(C["navy"]))
    palette.setColor(QPalette.WindowText,      QColor(C["light"]))
    palette.setColor(QPalette.Base,            QColor(C["navy2"]))
    palette.setColor(QPalette.Text,            QColor(C["light"]))
    palette.setColor(QPalette.Button,          QColor(C["navy3"]))
    palette.setColor(QPalette.ButtonText,      QColor(C["white"]))
    palette.setColor(QPalette.Highlight,       QColor(C["purple"]))
    palette.setColor(QPalette.HighlightedText, QColor(C["white"]))
    app.setPalette(palette)

    win = SecureUSApp()
    win.show()
    sys.exit(app.exec_())


# ── Colours ───────────────────────────────────────────────────────────────────

def _COLORS():
    return {
        "navy":    "#0a0f1e",
        "navy2":   "#111827",
        "navy3":   "#1a2235",
        "purple":  "#7c3aed",
        "purple2": "#6d28d9",
        "purple3": "#a78bfa",
        "slate":   "#8892a4",
        "light":   "#e8edf5",
        "white":   "#ffffff",
        "red":     "#ff4d6d",
        "amber":   "#ffa94d",
        "green":   "#4ade80",
    }

C = _COLORS()

OUI_MAP = {
    "00:50:56":"VMware","00:0c:29":"VMware","00:1a:11":"Google",
    "f4:f5:d8":"Google","b8:27:eb":"Raspberry Pi","dc:a6:32":"Raspberry Pi",
    "00:17:f2":"Apple","00:1b:63":"Apple","00:1c:b3":"Apple",
    "00:1e:52":"Apple","00:21:e9":"Apple","00:23:12":"Apple",
    "00:25:4b":"Apple","18:65:90":"Apple","3c:07:54":"Apple",
    "a4:c3:61":"Apple","00:14:22":"Dell","00:1a:4b":"Dell",
    "b8:ac:6f":"Dell","00:0d:3a":"Microsoft","00:15:5d":"Microsoft",
    "00:50:f2":"Microsoft","28:18:78":"Microsoft","00:23:ae":"Cisco",
    "00:1b:d4":"Cisco","fc:fb:fb":"Cisco","00:09:5b":"Netgear",
    "00:14:6c":"Netgear","c0:3f:0e":"TP-Link","f4:ec:38":"TP-Link",
    "50:c7:bf":"TP-Link","00:12:fb":"Samsung","00:15:99":"Samsung",
    "78:1f:db":"Amazon","fc:65:de":"Amazon","44:65:0d":"Amazon",
    "b4:7c:9c":"Amazon",
}

SUSPICIOUS_PORTS = {
    23: "Unencrypted remote access (Telnet)",
    445: "Windows file sharing (SMB)",
    3389: "Remote desktop access (RDP)",
    4444: "Common backdoor port",
    5900: "Remote desktop (VNC)",
    6667: "IRC (often used by malware)",
    1080: "Proxy port (SOCKS)",
    31337: "Classic hacking port",
}

KNOWN_BAD_RANGES = ["185.220.101.0/24", "198.98.51.0/24", "205.185.116.0/24"]

THREAT_ACTIONS = {
    "manufacturer could not be identified":
        "Check your router settings for this device. If you do not recognise it, block it.",
    "no readable name":
        "Log into your router and look up this device by IP. Disconnect it if unfamiliar.",
    "known threat list":
        "Block this IP in your router firewall immediately and scan any device that contacted it.",
    "multiple high-risk ports":
        "This device may be compromised. Disconnect it and run a security scan.",
    "port":
        "Close this port on the device or block it in your router firewall if unneeded.",
}


def get_action(threat_text):
    tl = threat_text.lower()
    for key, action in THREAT_ACTIONS.items():
        if key in tl:
            return action
    return "Investigate this device. Disconnect it if you do not recognise it."


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_gateway():
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output("ipconfig", text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            for line in out.splitlines():
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) > 1 and parts[1].strip():
                        return parts[1].strip()
        else:
            out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
            parts = out.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return get_local_ip().rsplit(".", 1)[0] + ".1"


def get_network_range():
    return get_local_ip().rsplit(".", 1)[0] + ".0/24"


def mac_to_manufacturer(mac):
    if not mac or mac == "Unknown":
        return "Unknown"
    prefix = mac[:8].lower().replace("-", ":")
    return OUI_MAP.get(prefix, "Unknown")


def ping_host(ip, timeout=0.5):
    try:
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
            r = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
            r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except Exception:
        return False


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def is_local_ip(ip):
    """Return True only for RFC-1918 private addresses and link-local."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_link_local
    except Exception:
        return False

def get_arp_table():
    """Return ARP table entries for LOCAL network IPs only.
    External/public IPs appear in the ARP cache from recent internet
    connections but are not devices on your network."""
    arp = {}
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(["arp", "-a"], text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    mac = parts[1].strip().replace("-", ":").lower()
                    if mac not in ("ff:ff:ff:ff:ff:ff", "physical"):
                        try:
                            socket.inet_aton(ip)
                            if is_local_ip(ip):
                                arp[ip] = mac
                        except Exception:
                            pass
        else:
            out = subprocess.check_output(["arp", "-n"], text=True)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0].strip()
                    mac = parts[2].strip().lower()
                    if mac not in ("(incomplete)", "ff:ff:ff:ff:ff:ff"):
                        try:
                            socket.inet_aton(ip)
                            if is_local_ip(ip):
                                arp[ip] = mac
                        except Exception:
                            pass
    except Exception:
        pass
    return arp



def scan_ports(ip, timeout=0.3):
    # Only port-scan local/private IPs. Scanning public internet IPs from the
    # ARP cache produces false positives (those servers run those ports normally).
    if not is_local_ip(ip):
        return []
    ports = [21, 22, 23, 25, 80, 443, 445, 3389, 5900, 8080, 4444, 1080, 6667, 31337]
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports


def is_bad_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        for net in KNOWN_BAD_RANGES:
            if addr in ipaddress.ip_network(net, strict=False):
                return True
    except Exception:
        pass
    return False


def score_device(device):
    threats = []
    score = 0
    open_ports   = device.get("open_ports", [])
    manufacturer = device.get("manufacturer", "Unknown")
    hostname     = device.get("hostname", "")
    ip           = device.get("ip", "")

    # External IPs (public internet) are not "devices on your network" —
    # skip manufacturer/hostname checks for them, only flag bad IPs.
    try:
        addr = ipaddress.ip_address(ip)
        local = addr.is_private or addr.is_link_local
    except Exception:
        local = True

    if local:
        if manufacturer == "Unknown":
            score += 20
            threats.append("Device manufacturer could not be identified")
        if not hostname:
            score += 10
            threats.append("Device has no readable name on the network")

    for port in open_ports:
        if port in SUSPICIOUS_PORTS:
            score += 35
            threats.append(f"Port {port} is open: {SUSPICIOUS_PORTS[port]}")
    if len([p for p in open_ports if p in SUSPICIOUS_PORTS]) >= 3:
        score += 30
        threats.append("Multiple high-risk ports open at the same time")
    if is_bad_ip(ip):
        score += 80
        threats.append("This IP address is on a known threat list")

    level = "critical" if score >= 60 else ("warning" if score >= 25 else "safe")
    return score, level, threats


# ── Workers ───────────────────────────────────────────────────────────────────

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QScrollArea, QSizePolicy, QFileDialog, QMessageBox,
    QProgressBar, QSpinBox, QComboBox,
)
from PyQt5.QtGui import QColor, QPalette, QFont


class ScanWorker(QThread):
    progress     = pyqtSignal(int, str)
    device_found = pyqtSignal(dict)
    finished     = pyqtSignal(list)
    error        = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            network  = ipaddress.ip_network(get_network_range(), strict=False)
            hosts    = list(network.hosts())
            gateway  = get_gateway()
            local_ip = get_local_ip()
            found    = []

            self.progress.emit(0, "Reading network table…")
            arp  = get_arp_table()
            alive = []
            lock  = threading.Lock()

            def check(ip_str):
                if self._stop:
                    return
                if ping_host(ip_str) or ip_str in arp:
                    with lock:
                        alive.append(ip_str)

            threads = []
            for i, host in enumerate(hosts):
                if self._stop:
                    return
                t = threading.Thread(target=check, args=(str(host),), daemon=True)
                threads.append(t)
                t.start()
                if i % 20 == 0:
                    self.progress.emit(int(i / len(hosts) * 40), f"Scanning… ({i}/{len(hosts)})")

            for t in threads:
                t.join(timeout=2)

            if self._stop:
                return

            # Filter to only local/private IPs — external IPs in the ARP cache
            # are internet destinations your machine connected to, not LAN devices.
            alive = [ip for ip in alive if is_local_ip(ip)]
            self.progress.emit(45, f"Found {len(alive)} devices. Checking each one…")

            for i, ip in enumerate(sorted(alive, key=lambda x: [int(p) for p in x.split(".")])):
                if self._stop:
                    return
                pct = 45 + int(i / max(len(alive), 1) * 50)
                self.progress.emit(pct, f"Checking {ip}…")

                mac          = arp.get(ip, "Unknown")
                hostname     = get_hostname(ip)
                manufacturer = mac_to_manufacturer(mac)
                open_ports   = scan_ports(ip)

                label = ("Gateway / Router" if ip == gateway else
                         "This device"      if ip == local_ip else
                         hostname or "")

                device = {
                    "ip": ip, "mac": mac, "hostname": hostname, "label": label,
                    "manufacturer": manufacturer, "open_ports": open_ports,
                    "is_gateway": ip == gateway, "is_local": ip == local_ip,
                    "first_seen": datetime.now().isoformat(),
                }
                score, level, threats = score_device(device)
                device.update({"score": score, "level": level, "threats": threats})
                if device["is_gateway"] and level != "critical":
                    device["level"] = "safe"
                    device["threats"] = []

                found.append(device)
                self.device_found.emit(device)

            self.progress.emit(100, "Scan complete.")
            self.finished.emit(found)

        except Exception as e:
            self.error.emit(str(e))


class WatchWorker(QThread):
    new_device = pyqtSignal(dict)
    tick       = pyqtSignal(str)

    def __init__(self, known_ips, interval=30):
        super().__init__()
        self.known_ips = set(known_ips)
        self.interval  = interval
        self._stop     = False

    def stop(self):
        self._stop = True

    def run(self):
        while not self._stop:
            self.tick.emit("Watching your network for changes…")
            arp = get_arp_table()
            for ip, mac in arp.items():
                if self._stop:
                    return
                if ip not in self.known_ips:
                    hostname     = get_hostname(ip)
                    manufacturer = mac_to_manufacturer(mac)
                    open_ports   = scan_ports(ip)
                    device = {
                        "ip": ip, "mac": mac, "hostname": hostname,
                        "label": hostname or "", "manufacturer": manufacturer,
                        "open_ports": open_ports, "is_gateway": False, "is_local": False,
                        "first_seen": datetime.now().isoformat(),
                    }
                    score, level, threats = score_device(device)
                    device.update({"score": score, "level": level, "threats": threats})
                    self.known_ips.add(ip)
                    self.new_device.emit(device)

            for _ in range(self.interval * 2):
                if self._stop:
                    return
                time.sleep(0.5)


# ── Stylesheet ────────────────────────────────────────────────────────────────

APP_STYLE = f"""
QMainWindow, QWidget {{
    background-color: {C['navy']};
    color: {C['light']};
    font-family: 'Segoe UI', 'SF Pro Display', Arial, sans-serif;
}}
QLabel {{ color: {C['light']}; background: transparent; }}
QPushButton {{
    border: none; border-radius: 7px;
    padding: 10px 22px; font-size: 13px; font-weight: 600;
}}
QPushButton:disabled {{ opacity: 0.4; }}
QTableWidget {{
    background-color: {C['navy2']};
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 10px;
    gridline-color: rgba(255,255,255,0.04);
    color: {C['light']}; font-size: 13px; outline: none;
}}
QTableWidget::item {{ padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.04); }}
QTableWidget::item:selected {{ background-color: rgba(124,58,237,0.15); color: {C['white']}; }}
QHeaderView::section {{
    background-color: {C['navy3']}; color: {C['slate']};
    font-size: 11px; font-weight: 700; letter-spacing: 1px;
    padding: 10px 12px; border: none;
    border-bottom: 1px solid rgba(255,255,255,0.06);
}}
QScrollBar:vertical {{
    background: {C['navy2']}; width: 6px; border-radius: 3px;
}}
QScrollBar::handle:vertical {{
    background: rgba(124,58,237,0.4); border-radius: 3px; min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: {C['navy2']}; height: 6px; border-radius: 3px;
}}
QScrollBar::handle:horizontal {{
    background: rgba(124,58,237,0.4); border-radius: 3px;
}}
QProgressBar {{
    background: rgba(255,255,255,0.06); border-radius: 4px;
    height: 6px; border: none; color: transparent;
}}
QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 {C['purple']}, stop:1 {C['purple3']});
    border-radius: 4px;
}}
"""


def make_btn(text, style="purple", small=False):
    btn = QPushButton(text)
    size = "11px" if small else "13px"
    pad  = "7px 16px" if small else "11px 24px"
    styles = {
        "purple": f"""
            QPushButton {{ background:{C['purple']}; color:{C['white']};
                font-size:{size}; padding:{pad}; border-radius:7px; font-weight:700; }}
            QPushButton:hover {{ background:{C['purple2']}; }}
            QPushButton:disabled {{ background:rgba(124,58,237,0.3); color:rgba(255,255,255,0.4); }}""",
        "green": f"""
            QPushButton {{ background:rgba(74,222,128,0.12); color:{C['green']};
                border:1px solid rgba(74,222,128,0.3);
                font-size:{size}; padding:{pad}; border-radius:7px; font-weight:700; }}
            QPushButton:hover {{ background:rgba(74,222,128,0.22); }}
            QPushButton:disabled {{ opacity:0.4; }}""",
        "ghost": f"""
            QPushButton {{ background:rgba(255,255,255,0.04); color:{C['slate']};
                border:1px solid rgba(255,255,255,0.08);
                font-size:{size}; padding:{pad}; border-radius:7px; font-weight:600; }}
            QPushButton:hover {{ background:rgba(255,255,255,0.08); color:{C['light']}; }}
            QPushButton:disabled {{ opacity:0.4; }}""",
    }
    btn.setStyleSheet(styles.get(style, styles["ghost"]))
    return btn


def make_card(bg=None, border="rgba(255,255,255,0.06)", radius=12):
    f = QFrame()
    f.setStyleSheet(f"""QFrame {{
        background: {bg or C['navy2']};
        border: 1px solid {border};
        border-radius: {radius}px;
    }}""")
    return f


# ── Widgets ───────────────────────────────────────────────────────────────────

class StatusBadge(QLabel):
    STYLES = {
        "safe":     (C['green'],  "rgba(74,222,128,0.12)",  "rgba(74,222,128,0.25)",  "Safe"),
        "warning":  (C['amber'],  "rgba(255,169,77,0.12)",  "rgba(255,169,77,0.25)",  "Worth checking"),
        "critical": (C['red'],    "rgba(255,77,109,0.12)",  "rgba(255,77,109,0.25)",  "Needs attention"),
        "idle":     (C['slate'],  "rgba(136,146,164,0.1)",  "rgba(136,146,164,0.2)",  "Not scanned"),
    }
    def __init__(self, level="idle"):
        super().__init__()
        self.setAlignment(Qt.AlignCenter)
        self.set_level(level)

    def set_level(self, level):
        col, bg, border, text = self.STYLES.get(level, self.STYLES["idle"])
        self.setText(text)
        self.setStyleSheet(f"""QLabel {{
            color:{col}; background:{bg}; border:1px solid {border};
            border-radius:5px; padding:3px 10px;
            font-size:11px; font-weight:700; letter-spacing:0.5px;
        }}""")


class BigStatusPanel(QFrame):
    def __init__(self):
        super().__init__()
        self._build()

    def _build(self):
        self.setStyleSheet(f"""QFrame {{
            background:{C['navy3']}; border:1px solid rgba(255,255,255,0.06); border-radius:14px;
        }}""")
        outer = QHBoxLayout(self)
        outer.setContentsMargins(28, 22, 28, 22)
        outer.setSpacing(20)

        self.icon_lbl = QLabel("📡")
        self.icon_lbl.setStyleSheet("font-size:36px; background:transparent;")

        text_col = QVBoxLayout()
        text_col.setSpacing(4)
        self.verdict_lbl = QLabel("Ready to scan")
        self.verdict_lbl.setStyleSheet(
            f"font-size:20px; font-weight:700; color:{C['white']}; background:transparent;")
        self.desc_lbl = QLabel("Press Scan Now to check every device on your network.")
        self.desc_lbl.setStyleSheet(
            f"font-size:13px; color:{C['slate']}; background:transparent;")
        self.desc_lbl.setWordWrap(True)
        text_col.addWidget(self.verdict_lbl)
        text_col.addWidget(self.desc_lbl)

        stats = QHBoxLayout()
        stats.setSpacing(32)
        self.s_devices = self._stat("Devices found")
        self.s_threats = self._stat("Alerts")
        self.s_safe    = self._stat("Safe devices")
        for w in [self.s_devices, self.s_threats, self.s_safe]:
            stats.addWidget(w)

        outer.addWidget(self.icon_lbl)
        outer.addLayout(text_col, 1)
        outer.addLayout(stats)

    def _stat(self, label_text):
        w = QFrame()
        w.setStyleSheet("background:transparent; border:none;")
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(2)
        val = QLabel("—")
        val.setStyleSheet(
            f"font-size:26px; font-weight:700; color:{C['white']}; background:transparent;")
        val.setAlignment(Qt.AlignCenter)
        lbl = QLabel(label_text)
        lbl.setStyleSheet(
            f"font-size:11px; color:{C['slate']}; background:transparent; letter-spacing:0.5px;")
        lbl.setAlignment(Qt.AlignCenter)
        v.addWidget(val)
        v.addWidget(lbl)
        w._val = val
        return w

    def update(self, level, verdict, desc, n_devices=None, n_threats=None, n_safe=None):
        icons   = {"safe":"✅","warning":"⚠️","critical":"🚨","scanning":"🔄","idle":"📡"}
        colors  = {"safe":C['green'],"warning":C['amber'],"critical":C['red'],
                   "scanning":C['purple3'],"idle":C['light']}
        borders = {"safe":"rgba(74,222,128,0.25)","warning":"rgba(255,169,77,0.3)",
                   "critical":"rgba(255,77,109,0.3)","scanning":"rgba(124,58,237,0.25)",
                   "idle":"rgba(255,255,255,0.06)"}
        self.icon_lbl.setText(icons.get(level, "📡"))
        col    = colors.get(level, C['light'])
        border = borders.get(level, "rgba(255,255,255,0.06)")
        self.verdict_lbl.setText(verdict)
        self.verdict_lbl.setStyleSheet(
            f"font-size:20px; font-weight:700; color:{col}; background:transparent;")
        self.desc_lbl.setText(desc)
        self.setStyleSheet(f"""QFrame {{
            background:{C['navy3']}; border:1px solid {border}; border-radius:14px;
        }}""")
        if n_devices is not None:
            self.s_devices._val.setText(str(n_devices))
        if n_threats is not None:
            self.s_threats._val.setText(str(n_threats))
            threat_col = C['red'] if n_threats > 0 else C['white']
            self.s_threats._val.setStyleSheet(
                f"font-size:26px; font-weight:700; color:{threat_col}; background:transparent;")
        if n_safe is not None:
            self.s_safe._val.setText(str(n_safe))


class AlertsPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setStyleSheet(f"""QFrame {{
            background:{C['navy2']}; border:1px solid rgba(255,255,255,0.06); border-radius:12px;
        }}""")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        header = QFrame()
        header.setStyleSheet(f"""QFrame {{
            background:{C['navy3']}; border:none;
            border-top-left-radius:12px; border-top-right-radius:12px;
            border-bottom:1px solid rgba(255,255,255,0.05);
        }}""")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(16, 12, 16, 12)
        title = QLabel("WHAT TO LOOK AT")
        title.setStyleSheet(
            f"font-size:11px; font-weight:700; color:{C['slate']}; letter-spacing:1px; background:transparent;")
        self.count_lbl = QLabel("0 alerts")
        self.count_lbl.setStyleSheet(
            f"font-size:11px; color:{C['slate']}; background:transparent;")
        hl.addWidget(title)
        hl.addStretch()
        hl.addWidget(self.count_lbl)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border:none; background:transparent; }")

        self.content = QWidget()
        self.content.setStyleSheet("background:transparent;")
        self.cl = QVBoxLayout(self.content)
        self.cl.setContentsMargins(16, 12, 16, 12)
        self.cl.setSpacing(8)
        self.cl.addStretch()

        scroll.setWidget(self.content)
        outer.addWidget(header)
        outer.addWidget(scroll)
        self._items = []

    def clear(self):
        for item in self._items:
            self.cl.removeWidget(item)
            item.deleteLater()
        self._items = []
        self.count_lbl.setText("0 alerts")

    def add_alert(self, device, threat_text, action_text, level="critical"):
        colors = {
            "critical": ("rgba(255,77,109,0.04)",  "rgba(255,77,109,0.15)",  C['red']),
            "warning":  ("rgba(255,169,77,0.04)",   "rgba(255,169,77,0.15)",  C['amber']),
        }
        bg, border, dot_col = colors.get(level, colors["warning"])

        item = QFrame()
        item.setStyleSheet(f"""QFrame {{
            background:{bg}; border:1px solid {border}; border-radius:8px;
        }}""")
        v = QVBoxLayout(item)
        v.setContentsMargins(14, 12, 14, 12)
        v.setSpacing(5)

        top = QHBoxLayout()
        dot = QLabel("●")
        dot.setStyleSheet(f"color:{dot_col}; font-size:8px; background:transparent;")
        msg = QLabel(threat_text)
        msg.setStyleSheet(
            f"font-size:13px; font-weight:600; color:{C['light']}; background:transparent;")
        msg.setWordWrap(True)
        top.addWidget(dot)
        top.addWidget(msg, 1)

        name = device.get("label") or device.get("hostname") or ""
        ip_str = f"Device: {device['ip']}" + (f"  |  {name}" if name else "")
        ip_lbl = QLabel(ip_str)
        ip_lbl.setStyleSheet(
            f"font-size:11px; color:{C['slate']}; background:transparent;")

        action = QLabel(f"What to do: {action_text}")
        action.setStyleSheet(
            f"font-size:11px; color:{C['purple3']}; font-weight:600; background:transparent;")
        action.setWordWrap(True)

        v.addLayout(top)
        v.addWidget(ip_lbl)
        v.addWidget(action)

        self.cl.insertWidget(self.cl.count() - 1, item)
        self._items.append(item)
        n = len(self._items)
        self.count_lbl.setText(f"{n} alert{'s' if n != 1 else ''}")


# ── Main window ───────────────────────────────────────────────────────────────

class SecureUSApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureUS Network Monitor")
        self.setMinimumSize(1100, 720)
        self.resize(1260, 800)
        self.devices      = []
        self.scan_worker  = None
        self.watch_worker = None
        self.watching     = False
        # Timer state
        self._elapsed_secs = 0
        self._limit_secs   = 0   # 0 = no limit
        self._clock_timer  = QTimer(self)
        self._clock_timer.setInterval(1000)
        self._clock_timer.timeout.connect(self._tick_clock)
        self._build()
        self.setStyleSheet(APP_STYLE)
        # Auto-start scan immediately on open; timer runs until user stops it
        QTimer.singleShot(300, self.start_scan)

    def _build(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._nav())

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet(f"QScrollArea {{ border:none; background:{C['navy']}; }}")

        body = QWidget()
        body.setStyleSheet(f"background:{C['navy']};")
        self.ml = QVBoxLayout(body)
        self.ml.setContentsMargins(36, 28, 36, 36)
        self.ml.setSpacing(18)

        self._toolbar()
        self._progress_bar()
        self._status_panel()
        self._device_table()
        self._bottom_row()

        scroll.setWidget(body)
        root.addWidget(scroll, 1)
        root.addWidget(self._statusbar())

    def _nav(self):
        nav = QFrame()
        nav.setFixedHeight(58)
        nav.setStyleSheet(f"""QFrame {{
            background:rgba(10,15,30,0.97);
            border-bottom:1px solid rgba(124,58,237,0.12);
        }}""")
        hl = QHBoxLayout(nav)
        hl.setContentsMargins(32, 0, 32, 0)

        logo = QLabel(
            "Secure<span style='color:#a78bfa;font-style:italic;'>US</span>"
            "  <span style='color:#8892a4;font-size:13px;font-weight:400;'>Network Monitor</span>"
        )
        logo.setTextFormat(Qt.RichText)
        logo.setStyleSheet(
            "font-size:20px; font-weight:700; color:white; background:transparent;"
            "font-family:Georgia,'Times New Roman',serif; letter-spacing:-0.5px;")

        self.watch_badge = QLabel("● Watching")
        self.watch_badge.setStyleSheet(
            f"font-size:11px; font-weight:700; color:{C['red']};"
            f"background:rgba(255,77,109,0.12); border:1px solid rgba(255,77,109,0.25);"
            f"border-radius:10px; padding:3px 10px;")
        self.watch_badge.hide()

        # Launch web app button
        web_btn = make_btn("Open Web App", "ghost", small=True)
        web_btn.clicked.connect(self._open_web_app)

        hl.addWidget(logo)
        hl.addStretch()
        hl.addWidget(web_btn)
        hl.addWidget(self.watch_badge)
        return nav

    def _open_web_app(self):
        import webbrowser
        webbrowser.open("https://secureus-yv9w.onrender.com/upload")

    def _toolbar(self):
        row = QHBoxLayout()
        row.setSpacing(10)
        self.scan_btn   = make_btn("▶  Scan Now", "purple")
        self.stop_btn   = make_btn("■  Stop", "ghost")
        self.watch_btn  = make_btn("👁  Start Watching", "ghost")
        self.export_btn = make_btn("↓  Save CSV", "green")
        self.clear_btn  = make_btn("Clear", "ghost", small=True)
        self.stop_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.clear_btn.setEnabled(False)
        self.scan_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.watch_btn.clicked.connect(self.toggle_watch)
        self.export_btn.clicked.connect(self.export_csv)
        self.clear_btn.clicked.connect(self.clear_all)

        # Duration selector (optional auto-stop)
        dur_lbl = QLabel("Stop after:")
        dur_lbl.setStyleSheet(f"font-size:12px; color:{C['slate']}; background:transparent;")
        self.dur_spin = QSpinBox()
        self.dur_spin.setRange(0, 24)
        self.dur_spin.setValue(0)
        self.dur_spin.setSpecialValueText("Never")
        self.dur_spin.setFixedWidth(60)
        self.dur_spin.setStyleSheet(f"""
            QSpinBox {{ background:{C['navy3']}; color:{C['light']};
                border:1px solid rgba(255,255,255,0.12); border-radius:6px;
                padding:4px 6px; font-size:12px; }}
            QSpinBox::up-button, QSpinBox::down-button {{ width:16px; }}
        """)
        self.dur_unit = QComboBox()
        self.dur_unit.addItems(["min", "hr"])
        self.dur_unit.setFixedWidth(54)
        self.dur_unit.setStyleSheet(f"""
            QComboBox {{ background:{C['navy3']}; color:{C['light']};
                border:1px solid rgba(255,255,255,0.12); border-radius:6px;
                padding:4px 8px; font-size:12px; }}
            QComboBox::drop-down {{ border:none; width:18px; }}
            QComboBox QAbstractItemView {{ background:{C['navy3']}; color:{C['light']}; }}
        """)

        # Running timer display
        self.timer_lbl = QLabel("00:00:00")
        self.timer_lbl.setStyleSheet(
            f"font-size:14px; font-weight:700; color:{C['purple3']};"
            f"background:rgba(124,58,237,0.10); border:1px solid rgba(124,58,237,0.25);"
            f"border-radius:7px; padding:5px 14px;")
        self.timer_lbl.setFixedWidth(100)

        row.addWidget(self.scan_btn)
        row.addWidget(self.stop_btn)
        row.addWidget(self.watch_btn)
        row.addSpacing(10)
        row.addWidget(dur_lbl)
        row.addWidget(self.dur_spin)
        row.addWidget(self.dur_unit)
        row.addStretch()
        row.addWidget(self.timer_lbl)
        row.addSpacing(4)
        row.addWidget(self.clear_btn)
        row.addWidget(self.export_btn)
        self.ml.addLayout(row)

    def _progress_bar(self):
        self.pframe = QFrame()
        self.pframe.setStyleSheet("background:transparent; border:none;")
        v = QVBoxLayout(self.pframe)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(6)
        self.pbar = QProgressBar()
        self.pbar.setFixedHeight(6)
        self.pbar.setRange(0, 100)
        self.plbl = QLabel("")
        self.plbl.setStyleSheet(f"font-size:12px; color:{C['slate']}; background:transparent;")
        v.addWidget(self.pbar)
        v.addWidget(self.plbl)
        self.pframe.hide()
        self.ml.addWidget(self.pframe)

    def _status_panel(self):
        self.status = BigStatusPanel()
        self.ml.addWidget(self.status)

    def _device_table(self):
        th = QHBoxLayout()
        tl = QLabel("DEVICES ON YOUR NETWORK")
        tl.setStyleSheet(
            f"font-size:11px; font-weight:700; color:{C['slate']}; letter-spacing:1px; background:transparent;")
        self.count_lbl = QLabel("0 devices")
        self.count_lbl.setStyleSheet(
            f"font-size:11px; color:{C['slate']}; background:transparent;")
        th.addWidget(tl)
        th.addStretch()
        th.addWidget(self.count_lbl)
        self.ml.addLayout(th)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Status", "IP Address", "Name / Label", "Manufacturer", "Open Ports", "Risk"])
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.Stretch)
        h.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(280)
        self.ml.addWidget(self.table)

    def _bottom_row(self):
        row = QHBoxLayout()
        row.setSpacing(16)

        self.alerts = AlertsPanel()
        self.alerts.setMinimumHeight(260)

        info = QVBoxLayout()
        info.setSpacing(12)

        # Upload card
        uc = make_card(bg=C['navy3'], border="rgba(124,58,237,0.18)")
        uv = QVBoxLayout(uc)
        uv.setContentsMargins(20, 18, 20, 18)
        uv.setSpacing(8)
        ul = QLabel("GET THE FULL PICTURE")
        ul.setStyleSheet(
            f"font-size:10px; font-weight:700; color:{C['purple3']}; letter-spacing:1px; background:transparent;")
        ut = QLabel("Upload your results to SecureUS")
        ut.setStyleSheet(
            f"font-size:14px; font-weight:700; color:{C['white']}; background:transparent;")
        ud = QLabel(
            "Save the CSV and upload it to secureus.com for a full AI-powered threat report on every connection and device.")
        ud.setStyleSheet(f"font-size:12px; color:{C['slate']}; background:transparent;")
        ud.setWordWrap(True)
        ub = make_btn("Save CSV and Open SecureUS", "purple", small=True)
        ub.clicked.connect(self.export_and_open)
        uv.addWidget(ul)
        uv.addWidget(ut)
        uv.addWidget(ud)
        uv.addWidget(ub)

        # Legend card
        lc = make_card(bg=C['navy3'])
        lv = QVBoxLayout(lc)
        lv.setContentsMargins(20, 18, 20, 18)
        lv.setSpacing(10)
        ll = QLabel("HOW TO READ THIS")
        ll.setStyleSheet(
            f"font-size:10px; font-weight:700; color:{C['slate']}; letter-spacing:1px; background:transparent;")
        lv.addWidget(ll)
        for icon, text in [
            ("✅", "Safe — device looks normal"),
            ("⚠️", "Worth checking — something unusual"),
            ("🚨", "Needs attention — take action now"),
        ]:
            r = QHBoxLayout()
            il = QLabel(icon)
            il.setStyleSheet("font-size:14px; background:transparent;")
            tl2 = QLabel(text)
            tl2.setStyleSheet(f"font-size:12px; color:{C['slate']}; background:transparent;")
            r.addWidget(il)
            r.addWidget(tl2, 1)
            lv.addLayout(r)

        info.addWidget(uc)
        info.addWidget(lc)
        info.addStretch()

        row.addWidget(self.alerts, 3)
        row.addLayout(info, 2)
        self.ml.addLayout(row)

    def _statusbar(self):
        bar = QFrame()
        bar.setFixedHeight(34)
        bar.setStyleSheet(f"""QFrame {{
            background:{C['navy2']}; border-top:1px solid rgba(255,255,255,0.05);
        }}""")
        hl = QHBoxLayout(bar)
        hl.setContentsMargins(24, 0, 24, 0)
        self.status_lbl = QLabel("Ready to scan your network.")
        self.status_lbl.setStyleSheet(
            f"font-size:11px; color:{C['slate']}; background:transparent;")
        info = QLabel(f"Your IP: {get_local_ip()}    Network: {get_network_range()}")
        info.setStyleSheet(
            f"font-size:11px; color:rgba(136,146,164,0.5); background:transparent;")
        hl.addWidget(self.status_lbl)
        hl.addStretch()
        hl.addWidget(info)
        return bar

    # ── Scan ──────────────────────────────────────────────────────────────

    def start_scan(self):
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.scan_worker.wait()
        self.clear_all()
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning…")
        self.stop_btn.setEnabled(True)
        self.pframe.show()
        self.pbar.setValue(0)
        self.status.update("scanning", "Checking your network…",
            "This takes about 30–60 seconds depending on how many devices are connected.")
        # Start the elapsed clock — it keeps running through watch phase
        self._elapsed_secs = 0
        self.timer_lbl.setText("00:00:00")
        val  = self.dur_spin.value()
        unit = self.dur_unit.currentText()
        self._limit_secs = (val * 60 if unit == "min" else val * 3600) if val > 0 else 0
        self._clock_timer.start()
        self.scan_worker = ScanWorker()
        self.scan_worker.progress.connect(self._on_progress)
        self.scan_worker.device_found.connect(self._on_device)
        self.scan_worker.finished.connect(self._on_done)
        self.scan_worker.error.connect(self._on_error)
        self.scan_worker.start()

    def stop_scan(self):
        """Stop everything — scan and watch — and freeze the timer."""
        self._clock_timer.stop()
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
        self._stop_watch()
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("▶  Scan Again")
        self.stop_btn.setEnabled(False)
        self.pframe.hide()
        self.status_lbl.setText("Stopped.")
        if self.devices:
            self.export_btn.setEnabled(True)
            self.clear_btn.setEnabled(True)
            self.status.update("idle", "Stopped",
                f"{len(self.devices)} devices found. Press Scan Again to restart.")

    def _tick_clock(self):
        self._elapsed_secs += 1
        h = self._elapsed_secs // 3600
        m = (self._elapsed_secs % 3600) // 60
        s = self._elapsed_secs % 60
        self.timer_lbl.setText(f"{h:02d}:{m:02d}:{s:02d}")
        # Auto-stop when time limit reached (0 = no limit)
        if self._limit_secs > 0 and self._elapsed_secs >= self._limit_secs:
            self.stop_scan()

    def _on_progress(self, pct, msg):
        self.pbar.setValue(pct)
        self.plbl.setText(msg)
        self.status_lbl.setText(msg)

    def _on_device(self, device):
        self.devices.append(device)
        self._add_row(device)
        n = len(self.devices)
        self.count_lbl.setText(f"{n} device{'s' if n != 1 else ''}")

    def _add_row(self, device):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setRowHeight(row, 46)
        level = device.get("level", "safe")
        icons = {"safe": "✅", "warning": "⚠️", "critical": "🚨"}

        def cell(text, color=None, align=None):
            item = QTableWidgetItem(text)
            if color:
                item.setForeground(QColor(color))
            if align:
                item.setTextAlignment(align)
            return item

        self.table.setItem(row, 0, cell(icons.get(level, "✅"), align=Qt.AlignCenter))
        self.table.setItem(row, 1, cell(device.get("ip", ""), C['white']))

        name = device.get("label") or device.get("hostname") or "—"
        self.table.setItem(row, 2, cell(name, C['light']))
        self.table.setItem(row, 3, cell(device.get("manufacturer", "Unknown"), C['slate']))

        ports = device.get("open_ports", [])
        port_str = ", ".join(str(p) for p in ports) if ports else "None"
        port_col  = C['red'] if any(p in SUSPICIOUS_PORTS for p in ports) else C['slate']
        self.table.setItem(row, 4, cell(port_str, port_col))

        badge = StatusBadge(level)
        self.table.setCellWidget(row, 5, badge)

        for threat in device.get("threats", []):
            action = get_action(threat)
            self.alerts.add_alert(device, threat, action, level)

    def _on_done(self, devices):
        self.devices = devices
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("▶  Scan Again")
        self.pframe.hide()
        self.export_btn.setEnabled(True)
        self.clear_btn.setEnabled(True)
        # Clock keeps running — it only stops when the user hits Stop

        n_critical = sum(1 for d in devices if d["level"] == "critical")
        n_warning  = sum(1 for d in devices if d["level"] == "warning")
        n_threats  = n_critical + n_warning
        n_safe     = sum(1 for d in devices if d["level"] == "safe")

        if n_critical > 0:
            self.status.update("critical", "Suspicious activity detected",
                f"{n_critical} device{'s' if n_critical != 1 else ''} need immediate attention. See the alerts below.",
                len(devices), n_threats, n_safe)
        elif n_warning > 0:
            self.status.update("warning", "Something looks unusual",
                f"{n_warning} device{'s' if n_warning != 1 else ''} worth taking a closer look at.",
                len(devices), n_threats, n_safe)
        else:
            self.status.update("safe", "Your network looks safe — now watching for changes",
                f"All {len(devices)} device{'s' if len(devices) != 1 else ''} passed the check. Monitoring for new devices.",
                len(devices), 0, n_safe)

        self.status_lbl.setText(
            f"Scan complete — {len(devices)} devices found, {n_threats} alerts. Watching for changes…")

        if not self.watching:
            self._start_watch([d["ip"] for d in devices])

    def _on_error(self, msg):
        self._clock_timer.stop()
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("▶  Scan Now")
        self.stop_btn.setEnabled(False)
        self.pframe.hide()
        self.status_lbl.setText(f"Error: {msg}")
        self.status.update("idle", "Scan failed",
            f"Something went wrong: {msg}. Make sure you are connected to a network and try again.")

    # ── Watch ──────────────────────────────────────────────────────────────

    def toggle_watch(self):
        if self.watching:
            self._stop_watch()
        else:
            self._start_watch([d["ip"] for d in self.devices])

    def _start_watch(self, known_ips):
        if self.watch_worker and self.watch_worker.isRunning():
            return
        self.watching = True
        self.watch_badge.show()
        self.watch_btn.setText("■  Stop Watching")
        self.watch_worker = WatchWorker(known_ips)
        self.watch_worker.new_device.connect(self._on_new_device)
        self.watch_worker.tick.connect(lambda s: self.status_lbl.setText(s))
        self.watch_worker.start()

    def _stop_watch(self):
        self.watching = False
        self.watch_badge.hide()
        self.watch_btn.setText("👁  Start Watching")
        if self.watch_worker:
            self.watch_worker.stop()
        # Clock stops when watching stops
        self._clock_timer.stop()
        self.stop_btn.setEnabled(False)

    def _on_new_device(self, device):
        self.devices.append(device)
        self._add_row(device)
        n = len(self.devices)
        self.count_lbl.setText(f"{n} device{'s' if n != 1 else ''}")
        level = device["level"]
        name  = device.get("label") or device.get("ip", "Unknown")
        if level == "critical":
            self.status.update("critical", "New suspicious device detected",
                f"An unknown device just joined your network: {name}. Check the alerts panel.")
        elif level == "warning":
            self.status.update("warning", "New device joined your network",
                f"{name} just connected and has been flagged for review.")

    # ── Export ────────────────────────────────────────────────────────────

    def _write_csv(self, path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "src_ip", "dst_ip", "mac", "hostname",
                         "manufacturer", "open_ports", "risk_level", "threats"])
            ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            gw  = get_gateway()
            for d in self.devices:
                w.writerow([
                    ts,
                    d.get("ip", ""),
                    gw,
                    d.get("mac", ""),
                    d.get("hostname", ""),
                    d.get("manufacturer", ""),
                    " ".join(str(p) for p in d.get("open_ports", [])),
                    d.get("level", ""),
                    " | ".join(d.get("threats", [])),
                ])

    def export_csv(self):
        if not self.devices:
            QMessageBox.information(self, "No data", "Run a scan first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save scan",
            f"secureus_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV files (*.csv)")
        if not path:
            return
        self._write_csv(path)
        QMessageBox.information(self, "Saved",
            f"Scan saved to:\n{path}\n\nUpload this file to SecureUS for a full AI report.")

    def export_and_open(self):
        if not self.devices:
            QMessageBox.information(self, "No data", "Run a scan first.")
            return
        import tempfile, webbrowser
        path = os.path.join(
            tempfile.gettempdir(),
            f"secureus_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        self._write_csv(path)
        webbrowser.open("https://secureus.com/upload")
        QMessageBox.information(self, "Ready",
            f"Your scan has been saved to:\n{path}\n\n"
            "SecureUS has opened in your browser. Upload this file for a full AI-powered report.")

    # ── Clear ─────────────────────────────────────────────────────────────

    def clear_all(self):
        self.devices = []
        self.table.setRowCount(0)
        self.alerts.clear()
        self.count_lbl.setText("0 devices")
        self.export_btn.setEnabled(False)
        self.clear_btn.setEnabled(False)
        self.status.update("idle", "Ready to scan",
            "Press Scan Now to check every device on your network.")

    def closeEvent(self, event):
        self._clock_timer.stop()
        if self.scan_worker:
            self.scan_worker.stop()
        if self.watch_worker:
            self.watch_worker.stop()
        event.accept()


if __name__ == "__main__":
    main()
