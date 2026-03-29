#!/usr/bin/env python3
"""
Local SIEM - Blue Team Security Monitor for macOS (Apple Silicon)
Monitors CPU, GPU, RAM, Network connections, detects threats, and manages IP blocking.
"""

import ipaddress
import json
import os
import re
import socket
import subprocess
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import psutil
from flask import Flask, send_file, jsonify, request
from flask_socketio import SocketIO, emit

_HERE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=_HERE, template_folder=_HERE)
app.config['SECRET_KEY'] = 'siem-local-only'
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

# ─── Global State ─────────────────────────────────────────────────────────────

blocked_ips: set = set()
threat_events: deque = deque(maxlen=1000)
event_id_counter = 0

# Per-IP tracking for threat detection
# ip -> list of (timestamp, port)
connection_history: dict = defaultdict(list)
# ip -> list of timestamps (for rate detection)
connection_rates: dict = defaultdict(list)
# Set of (ip, local_port) pairs we have already fired an alert for in this session
alerted_connections: set = set()

# Network I/O history for real-time chart (60 data points = ~60 seconds)
net_history = {
    'sent':   deque(maxlen=60),
    'recv':   deque(maxlen=60),
    'labels': deque(maxlen=60),
}
_net_baseline = {'bytes_sent': 0, 'bytes_recv': 0, 'ts': 0.0}

# ─── Threat Knowledge Base ────────────────────────────────────────────────────

# Ports associated with common RATs, shells, C2 frameworks, or unusual inbound
SUSPICIOUS_PORTS = {
    4444, 4445, 4446,       # Metasploit default
    1234, 31337,            # classic hacker ports
    12345, 54321,           # common backdoor defaults
    6666, 6667, 6668, 6669, # IRC/botnet C2
    9001, 9030,             # Tor
    8443, 8888, 9090,       # common proxy/C2 web ports
    23,                     # Telnet
    513, 514,               # rlogin / rsh
    135, 137, 138, 139,     # NetBIOS (unusual on Mac)
    1433, 3306, 5432, 27017, 6379,  # DBs - outbound is very suspicious
    5900, 5901,             # VNC
    3389,                   # RDP
}

# Connection states
HIGH_THREAT_STATUS = {'SYN_SENT', 'SYN_RECV'}

# Web ports to watch for "active websites"
WEB_PORTS = {80, 443, 8080, 8443, 8000, 3000, 4000}

# ─── DNS Resolution Cache ─────────────────────────────────────────────────────

# ip -> (hostname, resolved_at)
_dns_cache: dict = {}
_dns_lock = threading.Lock()
_dns_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix='dns')

# ip -> {host, ip, port, process, pid, first_seen, last_seen, count, threat}
active_sites: dict = {}

def _resolve(ip: str) -> str:
    """Reverse DNS lookup with 2s timeout. Returns hostname or the IP itself."""
    try:
        result = socket.gethostbyaddr(ip)
        return result[0]
    except Exception:
        return ip

def get_hostname(ip: str) -> str:
    """Return cached hostname for ip, triggering async lookup if not cached."""
    if not ip or _is_loopback(ip) or _is_private(ip):
        return ip
    with _dns_lock:
        entry = _dns_cache.get(ip)
        if entry:
            host, ts = entry
            # Re-resolve after 10 minutes
            if time.time() - ts < 600:
                return host
    # Blocking resolve (called from thread pool worker, so OK)
    host = _resolve(ip)
    with _dns_lock:
        _dns_cache[ip] = (host, time.time())
    return host

def _async_resolve(ip: str):
    """Submit a non-blocking DNS resolution for an IP."""
    with _dns_lock:
        if ip in _dns_cache:
            return
        # Placeholder while resolving
        _dns_cache[ip] = (ip, time.time())
    _dns_executor.submit(get_hostname, ip)

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    if not ip or ip == '*':
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_link_local or addr.is_loopback
    except ValueError:
        return True  # treat unparseable as local/safe

def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False

def _parse_addr(s: str):
    """Parse 'ip:port' or '[ipv6]:port' → (ip_str, port_int)."""
    s = s.strip()
    if s.startswith('['):
        m = re.match(r'\[([^\]]+)\]:(\d+)', s)
        if m:
            return m.group(1), int(m.group(2))
    elif ':' in s:
        parts = s.rsplit(':', 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            pass
    return s, 0

def _get_lsof_connections() -> list:
    """Parse lsof -i TCP to get all TCP connections including Chrome/sandboxed apps."""
    rows = []
    try:
        result = subprocess.run(
            ['lsof', '-i', 'TCP', '-n', '-P'],
            capture_output=True, text=True, timeout=8
        )
        for line in result.stdout.splitlines()[1:]:
            parts = line.split(None, 9)
            if len(parts) < 9:
                continue
            command     = parts[0]
            pid_str     = parts[1]
            addr_part   = parts[8].strip() if len(parts) > 8 else ''
            status_part = parts[9].strip() if len(parts) > 9 else ''

            # Status is in a separate column: "(ESTABLISHED)" / "(LISTEN)" etc.
            state_m = re.search(r'\((\w+)\)', status_part)
            status  = state_m.group(1) if state_m else 'N/A'

            if '->' in addr_part:
                local_s, remote_s = addr_part.split('->', 1)
                local_ip,  local_port  = _parse_addr(local_s)
                remote_ip, remote_port = _parse_addr(remote_s)
            else:
                local_ip, local_port = _parse_addr(addr_part)
                remote_ip, remote_port = '', 0

            try:
                pid = int(pid_str)
            except ValueError:
                pid = 0

            rows.append({
                'local_ip':    local_ip,
                'local_port':  local_port,
                'remote_ip':   remote_ip,
                'remote_port': remote_port,
                'status':      status,
                'pid':         pid,
                'process':     command,
            })
    except Exception:
        pass
    return rows

def _fmt_bytes(n: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def add_event(severity: str, event_type: str, source_ip: str, description: str, action: str = ''):
    global event_id_counter
    event_id_counter += 1
    evt = {
        'id':          event_id_counter,
        'timestamp':   datetime.now().strftime('%H:%M:%S'),
        'date':        datetime.now().strftime('%Y-%m-%d'),
        'severity':    severity,
        'type':        event_type,
        'source_ip':   source_ip or 'N/A',
        'description': description,
        'action':      action,
    }
    threat_events.appendleft(evt)
    socketio.emit('new_event', evt, namespace='/')
    return evt

# ─── System Metrics ───────────────────────────────────────────────────────────

def get_cpu_metrics() -> dict:
    freq = psutil.cpu_freq()
    load = os.getloadavg() if hasattr(os, 'getloadavg') else (0, 0, 0)
    return {
        'percent':     psutil.cpu_percent(interval=None),
        'per_core':    psutil.cpu_percent(percpu=True),
        'count':       psutil.cpu_count(logical=False),
        'logical':     psutil.cpu_count(logical=True),
        'freq_mhz':    round(freq.current) if freq else 0,
        'freq_max':    round(freq.max) if freq else 0,
        'load_1':      round(load[0], 2),
        'load_5':      round(load[1], 2),
        'load_15':     round(load[2], 2),
    }

def get_memory_metrics() -> dict:
    vm   = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        'total':        vm.total,
        'used':         vm.used,
        'available':    vm.available,
        'percent':      vm.percent,
        'total_fmt':    _fmt_bytes(vm.total),
        'used_fmt':     _fmt_bytes(vm.used),
        'swap_total':   swap.total,
        'swap_used':    swap.used,
        'swap_percent': swap.percent,
    }

def get_disk_metrics() -> dict:
    io = psutil.disk_io_counters()
    parts = []
    for p in psutil.disk_partitions():
        try:
            u = psutil.disk_usage(p.mountpoint)
            parts.append({
                'device':     p.device.split('/')[-1],
                'mountpoint': p.mountpoint,
                'total':      _fmt_bytes(u.total),
                'used':       _fmt_bytes(u.used),
                'percent':    u.percent,
            })
        except Exception:
            pass
    return {
        'read_bytes':  io.read_bytes if io else 0,
        'write_bytes': io.write_bytes if io else 0,
        'partitions':  parts[:4],
    }

def get_gpu_metrics() -> dict:
    """macOS GPU info via ioreg / system_profiler (no sudo needed)."""
    info = {'name': 'Unknown GPU', 'vram': 'N/A', 'activity': 'N/A', 'vendor': 'N/A'}
    try:
        result = subprocess.run(
            ['system_profiler', 'SPDisplaysDataType', '-json'],
            capture_output=True, text=True, timeout=5
        )
        data = json.loads(result.stdout)
        for item in data.get('SPDisplaysDataType', []):
            info['name']   = item.get('sppci_model', item.get('_name', 'Unknown'))
            info['vendor'] = item.get('sppci_vendor', 'N/A')
            info['vram']   = item.get('spdisplays_vram',
                             item.get('spdisplays_vram_shared', 'N/A'))
            break
    except Exception:
        pass
    # Try ioreg for real-time utilisation (Apple GPU)
    try:
        result = subprocess.run(
            ['ioreg', '-r', '-d', '1', '-w', '0', '-c', 'AGXAccelerator'],
            capture_output=True, text=True, timeout=3
        )
        m = re.search(r'"Device Utilization %"\s*=\s*(\d+)', result.stdout)
        if m:
            info['activity'] = m.group(1) + '%'
    except Exception:
        pass
    return info

def get_network_io() -> dict:
    """Returns per-second KB/s and updates rolling history."""
    counters = psutil.net_io_counters()
    now = time.time()
    elapsed = now - _net_baseline['ts'] if _net_baseline['ts'] else 1.0

    sent_rate = max(0, (counters.bytes_sent - _net_baseline['bytes_sent']) / elapsed)
    recv_rate = max(0, (counters.bytes_recv - _net_baseline['bytes_recv']) / elapsed)

    _net_baseline['bytes_sent'] = counters.bytes_sent
    _net_baseline['bytes_recv'] = counters.bytes_recv
    _net_baseline['ts']         = now

    label = datetime.now().strftime('%H:%M:%S')
    net_history['sent'].append(round(sent_rate / 1024, 1))
    net_history['recv'].append(round(recv_rate / 1024, 1))
    net_history['labels'].append(label)

    return {
        'sent_kbps':    round(sent_rate / 1024, 1),
        'recv_kbps':    round(recv_rate / 1024, 1),
        'total_sent':   _fmt_bytes(counters.bytes_sent),
        'total_recv':   _fmt_bytes(counters.bytes_recv),
        'packets_sent': counters.packets_sent,
        'packets_recv': counters.packets_recv,
        'errors_in':    counters.errin,
        'errors_out':   counters.errout,
        'history': {
            'sent':   list(net_history['sent']),
            'recv':   list(net_history['recv']),
            'labels': list(net_history['labels']),
        },
    }

# ─── Network Connection Analysis ─────────────────────────────────────────────

def _threat_level(conn) -> str:
    """Return threat level string for a connection."""
    if not conn.raddr:
        return 'NONE'

    ip   = conn.raddr.ip
    port = conn.raddr.port

    if ip in blocked_ips:
        return 'BLOCKED'

    if _is_loopback(ip) or _is_private(ip):
        return 'NONE'

    now     = time.time()
    threats = []

    # 1. Suspicious port — always a signal regardless of direction
    if port in SUSPICIOUS_PORTS:
        threats.append('suspicious_port')

    # 2. Port scan: same remote IP seen on many DIFFERENT ports within 60 s
    #    Legitimate browsers only use 443/80, so 10+ unique ports = real scan.
    history = connection_history[ip]
    history.append((now, port))
    connection_history[ip] = [(t, p) for t, p in history if now - t < 60]
    unique_ports = len({p for _, p in connection_history[ip]})
    if unique_ports >= 10:
        threats.append('port_scan')

    # 3. High connection RATE — browsers routinely open 50-80 conns to CDNs;
    #    only flag well above that to catch actual floods/scans (>150/min).
    rates = connection_rates[ip]
    rates.append(now)
    connection_rates[ip] = [t for t in rates if now - t < 60]
    if len(connection_rates[ip]) > 150:
        threats.append('high_rate')

    # 4. SYN flood / half-open scan indicator
    if conn.status in HIGH_THREAT_STATUS:
        threats.append('syn_state')

    # Severity: CRITICAL needs 2+ signals; HIGH needs 1 real signal
    if len(threats) >= 2:
        return 'CRITICAL'
    if 'port_scan' in threats or 'high_rate' in threats or 'syn_state' in threats:
        return 'HIGH'
    if 'suspicious_port' in threats:
        return 'MEDIUM'

    # External established — show as LOW (informational, not alarming)
    if conn.status == 'ESTABLISHED':
        return 'LOW'

    return 'NONE'

class _FakeConn:
    """Adapter so _threat_level() works with lsof rows."""
    def __init__(self, row):
        self.raddr  = type('A', (), {'ip': row['remote_ip'], 'port': row['remote_port']})() if row['remote_ip'] else None
        self.laddr  = type('A', (), {'ip': row['local_ip'],  'port': row['local_port']})()
        self.status = row['status']
        self.pid    = row['pid']

def get_connections() -> list:
    conns = []
    for row in _get_lsof_connections():
        if not row['local_ip']:
            continue
        fake   = _FakeConn(row)
        threat = _threat_level(fake)

        remote_ip   = row['remote_ip']
        remote_port = row['remote_port']

        # Trigger async DNS for external IPs
        if remote_ip and not _is_private(remote_ip):
            _async_resolve(remote_ip)

        with _dns_lock:
            cached   = _dns_cache.get(remote_ip)
            hostname = cached[0] if cached else (remote_ip or '')

        conns.append({
            'local':       f"{row['local_ip']}:{row['local_port']}",
            'remote':      f"{remote_ip}:{remote_port}" if remote_ip else '-',
            'remote_ip':   remote_ip,
            'remote_port': remote_port,
            'hostname':    hostname,
            'status':      row['status'],
            'pid':         row['pid'],
            'process':     row['process'],
            'threat':      threat,
            'private':     _is_private(remote_ip) if remote_ip else True,
        })

    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'BLOCKED': 3, 'LOW': 4, 'NONE': 5}
    conns.sort(key=lambda x: order.get(x['threat'], 9))
    return conns

def update_active_sites(conns: list):
    """Track external web connections with resolved hostnames."""
    now = time.time()
    seen_keys = set()
    for c in conns:
        ip   = c.get('remote_ip', '')
        port = c.get('remote_port', 0)
        # Include all external ESTABLISHED connections (IPv4 and IPv6)
        if not ip or c.get('private') or c.get('status') not in ('ESTABLISHED',):
            continue
        # Track all external ESTABLISHED connections, highlight web ports
        key = ip
        seen_keys.add(key)
        hostname = c.get('hostname', ip)
        if key in active_sites:
            active_sites[key]['last_seen']  = now
            active_sites[key]['count']     += 1
            active_sites[key]['hostname']   = hostname
            active_sites[key]['process']    = c.get('process', '-')
            active_sites[key]['port']       = port
            active_sites[key]['threat']     = c.get('threat', 'NONE')
        else:
            active_sites[key] = {
                'ip':         ip,
                'hostname':   hostname,
                'port':       port,
                'process':    c.get('process', '-'),
                'first_seen': now,
                'last_seen':  now,
                'count':      1,
                'threat':     c.get('threat', 'NONE'),
                'web':        port in WEB_PORTS,
            }
    # Expire sites not seen for 120 seconds
    expired = [k for k, v in active_sites.items() if now - v['last_seen'] > 120]
    for k in expired:
        del active_sites[k]

def get_active_sites_payload() -> list:
    now = time.time()
    rows = []
    for v in sorted(active_sites.values(), key=lambda x: x['last_seen'], reverse=True):
        rows.append({
            **v,
            'age_s':      int(now - v['first_seen']),
            'idle_s':     int(now - v['last_seen']),
        })
    return rows

def get_listening_ports() -> list:
    seen   = set()
    result = []
    for row in _get_lsof_connections():
        if row['status'] == 'LISTEN' and row['local_port']:
            k = row['local_port']
            if k in seen:
                continue
            seen.add(k)
            result.append({
                'address': f"{row['local_ip']}:{row['local_port']}",
                'port':    row['local_port'],
                'process': row['process'],
                'pid':     row['pid'],
                'flagged': row['local_port'] in SUSPICIOUS_PORTS,
            })
    return sorted(result, key=lambda x: x['port'])

def get_network_routes() -> list:
    routes = []
    try:
        out = subprocess.run(
            ['netstat', '-rn'], capture_output=True, text=True, timeout=5
        ).stdout
        for line in out.splitlines()[4:]:
            parts = line.split()
            if len(parts) >= 4:
                routes.append({
                    'dest':      parts[0],
                    'gateway':   parts[1],
                    'flags':     parts[2],
                    'interface': parts[3],
                })
    except Exception:
        pass
    return routes[:25]

# ─── Camera & Microphone Privacy Monitor ─────────────────────────────────────

# Apps known to legitimately use the microphone
_MIC_APPS = {
    'zoom', 'facetime', 'discord', 'teams', 'webex', 'skype',
    'telegram', 'whatsapp', 'obs', 'audacity', 'quicktime',
    'google chrome', 'chrome', 'firefox', 'safari', 'opera',
    'siri', 'corespeech', 'speechrecognitiond', 'callservicesd',
    'meet', 'slack', 'signal', 'loom', 'screenflow',
}

_privacy_state = {'camera': False, 'mic': False, 'cam_app': '', 'mic_apps': []}
_privacy_last_check = 0.0

def _camera_status():
    """Returns (active: bool, app: str). Uses Apple Silicon ioreg keys."""
    # ── Apple Silicon (M1/M2/M3/M4): FrontCameraStreaming / FrontCameraActive ──
    try:
        r = subprocess.run(
            ['ioreg', '-l', '-d', '5'],
            capture_output=True, text=True, timeout=5
        )
        out = r.stdout
        streaming = re.search(r'"FrontCameraStreaming"\s*=\s*(Yes|No)', out)
        active    = re.search(r'"FrontCameraActive"\s*=\s*(Yes|No)', out)
        back      = re.search(r'"BackCameraActive"\s*=\s*(Yes|No)', out)
        is_on = any([
            streaming and streaming.group(1) == 'Yes',
            active    and active.group(1)    == 'Yes',
            back      and back.group(1)      == 'Yes',
        ])
        if is_on:
            return True, _find_camera_app()
    except Exception:
        pass
    # ── Intel Mac fallback: VDCAssistant process ──
    try:
        for daemon in ('VDCAssistant', 'CMIOExtensionCameraAssistant'):
            r = subprocess.run(['pgrep', '-x', daemon],
                               capture_output=True, text=True, timeout=2)
            if r.returncode == 0:
                return True, _find_camera_app()
    except Exception:
        pass
    return False, ''

def _find_camera_app() -> str:
    """Best-effort: find which app opened the camera via lsof."""
    try:
        r = subprocess.run(
            ['lsof', '-n', '-c', 'VDCAssistant'],
            capture_output=True, text=True, timeout=3
        )
        names = {ln.split()[0] for ln in r.stdout.splitlines()[1:] if ln}
        names.discard('VDCAssistant')
        if names:
            return ', '.join(sorted(names)[:3])
    except Exception:
        pass
    # Also check which foreground video apps are running
    try:
        r = subprocess.run(['ps', '-axo', 'comm='],
                           capture_output=True, text=True, timeout=3)
        video_apps = []
        for line in r.stdout.splitlines():
            app = line.strip().split('/')[-1].lower()
            if any(k in app for k in ('facetime', 'zoom', 'chrome', 'safari',
                                       'teams', 'discord', 'webex', 'meet')):
                video_apps.append(app)
        if video_apps:
            return ', '.join(sorted(set(video_apps))[:3])
    except Exception:
        pass
    return 'Unknown'

def _mic_status():
    """Returns (active: bool, apps: list[str]).
    Uses lsof coreaudio connections + known mic-app heuristic."""
    try:
        r = subprocess.run(['lsof', '-n'], capture_output=True, text=True, timeout=5)
        connected = set()
        for line in r.stdout.splitlines():
            if 'coreaudio' in line.lower():
                connected.add(line.split()[0].lower())
        mic_apps = sorted({a for a in connected
                           if any(m in a for m in _MIC_APPS)})
        # Also check for speechrecognitiond / callservicesd as strong mic indicators
        strong = any(a in connected for a in
                     ('speechrecognitiond', 'callservicesd', 'corespeechd',
                      'avconferenced', 'audiocapturerd'))
        return (bool(mic_apps) or strong), mic_apps
    except Exception:
        return False, []

def check_privacy():
    """Poll camera + mic state; fire events on state changes. Runs every 2 s."""
    global _privacy_last_check
    now = time.time()
    if now - _privacy_last_check < 2:
        return _privacy_state.copy()
    _privacy_last_check = now

    cam_on,  cam_app  = _camera_status()
    mic_on,  mic_apps = _mic_status()

    # ── Camera state change ──
    if cam_on != _privacy_state['camera']:
        _privacy_state['camera']  = cam_on
        _privacy_state['cam_app'] = cam_app
        if cam_on:
            add_event('HIGH', 'CAMERA_ON', 'localhost',
                      f'Camera activated — app: {cam_app or "Unknown"}',
                      'Verify this is authorized')
        else:
            add_event('INFO', 'CAMERA_OFF', 'localhost', 'Camera deactivated')

    # ── Mic state change ──
    if mic_on != _privacy_state['mic']:
        _privacy_state['mic']      = mic_on
        _privacy_state['mic_apps'] = mic_apps
        if mic_on:
            add_event('MEDIUM', 'MIC_ON', 'localhost',
                      f'Microphone activated — apps: {", ".join(mic_apps) or "Unknown"}',
                      'Verify this is authorized')
        else:
            add_event('INFO', 'MIC_OFF', 'localhost', 'Microphone deactivated')

    return _privacy_state.copy()

# ─── macOS Log Parsing (SSH / Auth brute-force detection) ────────────────────

_last_log_check = 0.0
_seen_log_ips: dict = defaultdict(int)  # ip -> failure_count this cycle

def check_auth_logs():
    global _last_log_check
    now = time.time()
    if now - _last_log_check < 30:
        return
    _last_log_check = now

    try:
        result = subprocess.run(
            ['log', 'show', '--last', '2m',
             '--predicate',
             'process == "sshd" OR process == "sudo" OR '
             'eventMessage CONTAINS "authentication failure" OR '
             'eventMessage CONTAINS "Invalid user"',
             '--style', 'compact'],
            capture_output=True, text=True, timeout=10
        )
        ip_failures: dict = defaultdict(int)
        for line in result.stdout.splitlines():
            m = re.search(r'(?:Failed password|Invalid user)[^\d]*(\d+\.\d+\.\d+\.\d+)', line)
            if m:
                ip_failures[m.group(1)] += 1
        for ip, count in ip_failures.items():
            if count >= 3 and _seen_log_ips.get(ip, 0) < count:
                _seen_log_ips[ip] = count
                add_event(
                    'HIGH', 'BRUTE_FORCE', ip,
                    f"Brute-force attempt: {count} auth failures from {ip}",
                    'Recommend: block IP'
                )
    except Exception:
        pass

# ─── Background Monitor Loop ─────────────────────────────────────────────────

def _monitor_loop():
    # Reset threat trackers so stale data from a previous run doesn't fire alerts
    connection_history.clear()
    connection_rates.clear()
    alerted_connections.clear()

    # Seed baseline
    c = psutil.net_io_counters()
    _net_baseline['bytes_sent'] = c.bytes_sent
    _net_baseline['bytes_recv'] = c.bytes_recv
    _net_baseline['ts']         = time.time()
    # Warm up cpu_percent (first call returns 0)
    psutil.cpu_percent(interval=None)
    time.sleep(0.5)

    while True:
        try:
            cpu    = get_cpu_metrics()
            memory = get_memory_metrics()
            disk   = get_disk_metrics()
            net_io = get_network_io()
            conns  = get_connections()

            # Fire events for new high-threat connections
            for conn in conns:
                if conn['threat'] in ('HIGH', 'CRITICAL') and conn['remote_ip']:
                    key = (conn['remote_ip'], conn['local'])
                    if key not in alerted_connections:
                        alerted_connections.add(key)
                        add_event(
                            conn['threat'], 'THREAT_CONNECTION', conn['remote_ip'],
                            f"Suspicious connection {conn['remote_ip']}→{conn['local']} "
                            f"[{conn['process']}] status={conn['status']}",
                            'Investigate / Block'
                        )

            update_active_sites(conns)
            privacy = check_privacy()
            check_auth_logs()

            # Compute overall threat level
            tmap = {c['threat'] for c in conns}
            if 'CRITICAL' in tmap:
                tlevel, tlevel_color = 'CRITICAL', '#ff0000'
            elif 'HIGH' in tmap:
                tlevel, tlevel_color = 'HIGH', '#ff6600'
            elif 'MEDIUM' in tmap:
                tlevel, tlevel_color = 'MEDIUM', '#ffaa00'
            else:
                tlevel, tlevel_color = 'LOW', '#00ff88'

            payload = {
                'ts':             datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'cpu':            cpu,
                'memory':         memory,
                'disk':           disk,
                'network':        net_io,
                'connections':    conns,
                'conn_count':     len(conns),
                'external_conns': sum(1 for c in conns if not c['private'] and c['remote_ip']),
                'threat_level':   tlevel,
                'threat_color':   tlevel_color,
                'high_count':     sum(1 for c in conns if c['threat'] in ('HIGH', 'CRITICAL')),
                'medium_count':   sum(1 for c in conns if c['threat'] == 'MEDIUM'),
                'blocked_count':  len(blocked_ips),
                'event_count':    len(threat_events),
                'active_sites':   get_active_sites_payload(),
                'privacy':        privacy,
            }
            socketio.emit('metrics', payload, namespace='/')

        except Exception as e:
            pass

        time.sleep(1)

# ─── Flask Routes ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_file(os.path.join(_HERE, 'dashboard.html'))

@app.route('/api/status')
def api_status():
    return jsonify({
        'blocked_ips': list(blocked_ips),
        'events':      list(threat_events)[:100],
        'routes':      get_network_routes(),
        'listening':   get_listening_ports(),
        'gpu':         get_gpu_metrics(),
    })

@app.route('/api/block', methods=['POST'])
def api_block():
    ip = (request.get_json() or {}).get('ip', '').strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({'error': 'Invalid IP'}), 400

    if ip in blocked_ips:
        return jsonify({'status': 'already_blocked', 'ip': ip})

    blocked_ips.add(ip)

    # Try actual pf block (requires sudo; will silently fail otherwise)
    method = 'dashboard_only'
    try:
        r = subprocess.run(
            ['sudo', '-n', 'pfctl', '-t', 'siem_blocked', '-T', 'add', ip],
            capture_output=True, timeout=3
        )
        if r.returncode == 0:
            method = 'pf_firewall'
    except Exception:
        pass

    add_event('INFO', 'IP_BLOCKED', ip, f"IP {ip} blocked ({method})", f'Method: {method}')
    socketio.emit('blocked_update', list(blocked_ips), namespace='/')
    return jsonify({'status': 'blocked', 'ip': ip, 'method': method})

@app.route('/api/unblock', methods=['POST'])
def api_unblock():
    ip = (request.get_json() or {}).get('ip', '').strip()
    blocked_ips.discard(ip)
    try:
        subprocess.run(
            ['sudo', '-n', 'pfctl', '-t', 'siem_blocked', '-T', 'delete', ip],
            capture_output=True, timeout=3
        )
    except Exception:
        pass
    add_event('INFO', 'IP_UNBLOCKED', ip, f"IP {ip} unblocked")
    socketio.emit('blocked_update', list(blocked_ips), namespace='/')
    return jsonify({'status': 'unblocked', 'ip': ip})

@app.route('/api/events')
def api_events():
    return jsonify(list(threat_events))

# ─── Country flag emoji helper ────────────────────────────────────────────────

def _country_flag(code: str) -> str:
    if not code or len(code) != 2:
        return '🌐'
    return chr(0x1F1E6 + ord(code[0].upper()) - ord('A')) + \
           chr(0x1F1E6 + ord(code[1].upper()) - ord('A'))

# ─── IP Investigation ─────────────────────────────────────────────────────────

@app.route('/api/investigate/<path:ip>')
def api_investigate(ip):
    import urllib.request, urllib.error

    result = {
        'ip':        ip,
        'geo':       {},
        'rdns':      '',
        'traceroute': [],
        'connections': [],
        'whois_summary': '',
    }

    # 1. Geolocation via ip-api.com
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,isp,org,as,query,threat"
        with urllib.request.urlopen(url, timeout=5) as r:
            geo = json.loads(r.read().decode())
            if geo.get('status') == 'success':
                geo['flag'] = _country_flag(geo.get('countryCode', ''))
                result['geo'] = geo
    except Exception:
        pass

    # 2. Reverse DNS
    try:
        result['rdns'] = socket.gethostbyaddr(ip)[0]
    except Exception:
        result['rdns'] = ip

    # 3. Traceroute (max 15 hops, 1 probe, 2s timeout per hop)
    try:
        tr = subprocess.run(
            ['traceroute', '-m', '15', '-q', '1', '-w', '2', ip],
            capture_output=True, text=True, timeout=35
        )
        hops = []
        for line in tr.stdout.splitlines()[1:]:
            m = re.match(r'\s*(\d+)\s+(.+)', line)
            if not m:
                continue
            hop_num = int(m.group(1))
            rest = m.group(2).strip()
            if rest.startswith('*'):
                hops.append({'hop': hop_num, 'host': '*', 'ip': '', 'ms': ''})
                continue
            # Parse "hostname (ip)  x.xxx ms" or "ip  x.xxx ms"
            host_m = re.match(r'([^\s(]+)(?:\s+\(([^)]+)\))?\s+([\d.]+)\s+ms', rest)
            if host_m:
                h = host_m.group(1)
                raw_ip = host_m.group(2) or h
                ms = host_m.group(3)
                # Try geo for each hop
                hop_geo = {}
                try:
                    if not ipaddress.ip_address(raw_ip).is_private:
                        with urllib.request.urlopen(
                            f"http://ip-api.com/json/{raw_ip}?fields=country,countryCode,city,isp",
                            timeout=3
                        ) as r2:
                            hop_geo = json.loads(r2.read().decode())
                            hop_geo['flag'] = _country_flag(hop_geo.get('countryCode', ''))
                except Exception:
                    pass
                hops.append({'hop': hop_num, 'host': h, 'ip': raw_ip, 'ms': ms, 'geo': hop_geo})
            else:
                hops.append({'hop': hop_num, 'host': rest, 'ip': '', 'ms': ''})
        result['traceroute'] = hops
    except Exception as e:
        result['traceroute'] = [{'hop': 1, 'host': f'Error: {e}', 'ip': '', 'ms': ''}]

    # 4. Active connections from this IP right now
    try:
        active = [c for c in get_connections() if c.get('remote_ip') == ip]
        result['connections'] = active[:20]
    except Exception:
        pass

    # 5. Quick whois summary (first 15 lines)
    try:
        w = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=8)
        lines = [l for l in w.stdout.splitlines()
                 if l.strip() and not l.startswith('%') and not l.startswith('#')][:15]
        result['whois_summary'] = '\n'.join(lines)
    except Exception:
        pass

    return jsonify(result)

# ─── Socket.IO Events ─────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    emit('init', {
        'blocked_ips': list(blocked_ips),
        'events':      list(threat_events)[:100],
        'gpu':         get_gpu_metrics(),
        'routes':      get_network_routes(),
        'listening':   get_listening_ports(),
    })

@socketio.on('request_routes')
def on_routes():
    emit('routes_update', get_network_routes())

@socketio.on('request_listening')
def on_listening():
    emit('listening_update', get_listening_ports())

# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print()
    print('  ╔══════════════════════════════════════════╗')
    print('  ║   LOCAL SIEM  —  Blue Team Monitor       ║')
    print('  ║   Dashboard → http://localhost:5555      ║')
    print('  ╚══════════════════════════════════════════╝')
    print()

    add_event('INFO', 'SYSTEM_START', 'localhost',
              f'SIEM monitor started on {psutil.cpu_count()} CPU cores')

    t = threading.Thread(target=_monitor_loop, daemon=True)
    t.start()

    socketio.run(app, host='127.0.0.1', port=5555, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
