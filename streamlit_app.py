#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Custom sbx-native:
  - sing-box  (vless + ws, argo only)
  - cloudflared
  - komari agent  (only if KOMARI_SERVER + KOMARI_TOKEN are set)
  - HTTP disguise server (only `/`)
"""

import os, sys, json, time, re, base64, hashlib, shutil, signal, socket
import subprocess, threading, ctypes
from ctypes import c_int, c_char_p, c_void_p
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import quote

# ---------------- requests bootstrap ----------------
try:
    import requests
except ImportError:
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "requests"])
    except Exception as e:
        print(f"Failed to install requests: {e}", file=sys.stderr)
        sys.exit(1)
    import requests


# ======================== ENV ========================
UPLOAD_URL        = os.environ.get('UPLOAD_URL', '')
UUID              = os.environ.get('UUID', '0a6568ff-ea3c-4271-9020-450560e10d63')
ARGO_PORT         = int(os.environ.get('ARGO_PORT', '8001'))
ARGO_DOMAIN       = os.environ.get('ARGO_DOMAIN', '')
ARGO_AUTH         = os.environ.get('ARGO_AUTH', '')
CFIP              = os.environ.get('CFIP', 'spring.io')
CFPORT            = int(os.environ.get('CFPORT', '443'))
PORT              = int(os.environ.get('PORT', '3000'))
NAME              = os.environ.get('NAME', '')
CHAT_ID           = os.environ.get('CHAT_ID', '')
BOT_TOKEN         = os.environ.get('BOT_TOKEN', '')
FILE_PATH         = os.environ.get('FILE_PATH', '.cache')
WEB_FILE          = os.environ.get('WEB_FILE', 'index.html')
DISABLE_ARGO      = os.environ.get('DISABLE_ARGO', 'false').lower() in ('true', 'yes')
SHOW_LOG          = os.environ.get('SHOW_LOG', 'true').lower() not in ('false', 'disable', 'no')

# komari
KOMARI_SERVER           = os.environ.get('KOMARI_SERVER', '')
KOMARI_TOKEN            = os.environ.get('KOMARI_TOKEN', '')
KOMARI_INTERVAL         = int(os.environ.get('KOMARI_INTERVAL', '15'))
KOMARI_DISABLE_WEB_SSH  = os.environ.get('KOMARI_DISABLE_WEB_SSH', 'false').lower() in ('true', 'yes')
KOMARI_IGNORE_UNSAFE    = os.environ.get('KOMARI_IGNORE_UNSAFE_CERT', 'false').lower() in ('true', 'yes')

NEED_KOMARI       = bool(KOMARI_SERVER and KOMARI_TOKEN)
DISABLE_ARGO      = DISABLE_ARGO or not (ARGO_AUTH or True)  # argo always required here

STARTUP_RETRIES   = 3
CLEANUP_DELAY_SEC = 90


# ======================== helpers ========================
def log(*a, **kw):
    if SHOW_LOG:
        print(*a, **kw)


def get_arch() -> str:
    m = os.uname().machine.lower()
    return 'arm64' if m in ('arm64', 'aarch64') else 'amd64'


ARCH = get_arch()

ROOT             = os.getcwd()
runtimeFilePath  = os.path.abspath(os.path.join(ROOT, FILE_PATH))
sbxConfigPath    = os.path.join(runtimeFilePath, 'sbx.json')
komariConfigPath = os.path.join(runtimeFilePath, 'komari.json')
bootLogPath      = os.path.join(runtimeFilePath, 'boot.log')
subPath          = os.path.join(runtimeFilePath, 'sub.txt')
listPath         = os.path.join(runtimeFilePath, 'list.txt')
pidLockPath      = os.path.join(runtimeFilePath, 'app.pid')


def sha256_file(p: str) -> str:
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(4096), b''):
            h.update(b)
    return h.hexdigest()


def is_valid_port(v) -> bool:
    try:
        return v is not None and v != '' and 1 <= int(v) <= 65535
    except Exception:
        return False


def get_server_ip() -> str:
    for url, wrap in (
        ('http://ipv4.ip.sb', lambda t: t),
        ('http://ipv6.ip.sb', lambda t: f'[{t}]'),
    ):
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200 and r.text.strip():
                return wrap(r.text.strip())
        except Exception:
            pass
    return ''


def get_meta_info() -> str:
    try:
        r = requests.get('https://api.ip.sb/geoip', timeout=3)
        if r.status_code == 200:
            d = r.json()
            if d.get('country_code') and d.get('isp'):
                return f"{d['country_code']}-{d['isp']}".replace(' ', '_')
    except Exception:
        pass
    try:
        r = requests.get('http://ip-api.com/json', timeout=3)
        if r.status_code == 200:
            d = r.json()
            if d.get('status') == 'success' and d.get('countryCode') and d.get('org'):
                return f"{d['countryCode']}-{d['org']}".replace(' ', '_')
    except Exception:
        pass
    return 'Unknown'


# ======================== 清理 ========================
def _rm(path: str):
    try:
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        elif os.path.exists(path):
            os.unlink(path)
    except Exception:
        pass


def clear_dir(keep: set):
    if not os.path.exists(runtimeFilePath):
        return
    for f in os.listdir(runtimeFilePath):
        if f in keep:
            continue
        _rm(os.path.join(runtimeFilePath, f))


def clear_before_startup():
    """启动清理:保留 .so 与 app.pid,其余全清"""
    keep = {'app.pid'}
    if os.path.exists(runtimeFilePath):
        for f in os.listdir(runtimeFilePath):
            if f.endswith('.so'):
                keep.add(f)
    clear_dir(keep)
    tmp = os.path.join(ROOT, '.tmp')
    if os.path.exists(tmp):
        shutil.rmtree(tmp, ignore_errors=True)


def clear_after_startup():
    """90s 后:连 .so 一起清,保留 sub/list/pid"""
    clear_dir({'sub.txt', 'list.txt', 'app.pid'})


# ======================== PID lock ========================
def acquire_pid_lock():
    os.makedirs(runtimeFilePath, exist_ok=True)
    if os.path.exists(pidLockPath):
        try:
            with open(pidLockPath) as f:
                old = int(f.read().strip())
            if old != os.getpid():
                os.kill(old, 0)  # 存活检查
                try:
                    with open(f'/proc/{old}/cmdline', 'rb') as f:
                        cmd = f.read()
                    if b'python' in cmd or b'app.py' in cmd:
                        log(f'Killing stale process {old}')
                        os.kill(old, signal.SIGKILL)
                        time.sleep(1)
                except FileNotFoundError:
                    pass
        except (ValueError, ProcessLookupError, FileNotFoundError):
            pass
    with open(pidLockPath, 'w') as f:
        f.write(str(os.getpid()))


def release_pid_lock():
    try:
        if os.path.exists(pidLockPath):
            with open(pidLockPath) as f:
                if f.read().strip() == str(os.getpid()):
                    os.unlink(pidLockPath)
    except Exception:
        pass


# ======================== port cleanup ========================
def _port_in_use(port: int) -> bool:
    for host, fam in (('127.0.0.1', socket.AF_INET), ('::1', socket.AF_INET6)):
        try:
            with socket.socket(fam, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((host, port)) == 0:
                    return True
        except OSError:
            pass
    return False


def free_port(port: int, timeout: float = 10.0):
    if not _port_in_use(port):
        return True
    log(f'Freeing port {port} ...')
    for tool in (['lsof', '-ti', f':{port}'],
                 ['fuser', '-k', f'{port}/tcp']):
        try:
            r = subprocess.run(tool, capture_output=True, text=True, timeout=5)
            for pid_s in r.stdout.split():
                if pid_s.isdigit() and int(pid_s) != os.getpid():
                    try:
                        os.kill(int(pid_s), signal.SIGTERM)
                    except ProcessLookupError:
                        pass
        except FileNotFoundError:
            continue
        except Exception:
            pass
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _port_in_use(port):
            return True
        time.sleep(0.5)
    # SIGKILL 兜底
    try:
        r = subprocess.run(['lsof', '-ti', f':{port}'],
                           capture_output=True, text=True, timeout=5)
        for pid_s in r.stdout.split():
            if pid_s.isdigit() and int(pid_s) != os.getpid():
                try:
                    os.kill(int(pid_s), signal.SIGKILL)
                except ProcessLookupError:
                    pass
    except Exception:
        pass
    time.sleep(1)
    return not _port_in_use(port)


# ======================== download ========================
def download_library(url: str, filename: str, sha256: str = None) -> str:
    target = os.path.join(runtimeFilePath, filename)
    os.makedirs(runtimeFilePath, exist_ok=True)

    if os.path.exists(target) and (sha256 is None or sha256_file(target) == sha256):
        log(f'Using cached {target}')
        return target

    tmp = target + '.download'
    try:
        log(f'Downloading {url}')
        r = requests.get(url, stream=True, timeout=180, allow_redirects=True)
        r.raise_for_status()
        with open(tmp, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        if sha256 and sha256_file(tmp) != sha256:
            raise RuntimeError('sha256 mismatch')
        # 简单 ELF 头检查
        with open(tmp, 'rb') as f:
            if f.read(4) != b'\x7fELF':
                raise RuntimeError(f'{filename} is not a valid ELF file')
        os.replace(tmp, target)
        os.chmod(target, 0o755)
        return target
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except Exception:
                pass


def download_with_retry(url: str, filename: str, sha256: str = None, attempts: int = 3) -> str:
    last = None
    for i in range(attempts):
        try:
            return download_library(url, filename, sha256)
        except Exception as e:
            last = e
            log(f'Download {filename} attempt {i+1}/{attempts} failed: {e}')
            if i + 1 < attempts:
                time.sleep(2 * (i + 1))
    raise last


# ======================== argo / payloads ========================
def argo_type_write():
    """prepare tunnel.yml if using credentials-file mode"""
    if not ARGO_AUTH or not ARGO_DOMAIN:
        return
    if 'TunnelSecret' in ARGO_AUTH:
        with open(os.path.join(runtimeFilePath, 'tunnel.json'), 'w') as f:
            f.write(ARGO_AUTH)
        m = re.search(r'"TunnelID":\s*"([^"]+)"', ARGO_AUTH)
        tid = m.group(1) if m else ''
        yml = f"""tunnel: {tid}
credentials-file: {os.path.join(runtimeFilePath, 'tunnel.json')}
protocol: http2

ingress:
  - hostname: {ARGO_DOMAIN}
    service: http://localhost:{ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
        with open(os.path.join(runtimeFilePath, 'tunnel.yml'), 'w') as f:
            f.write(yml)


def is_quick_tunnel() -> bool:
    return not (ARGO_AUTH and ARGO_DOMAIN)


def cloudflared_payload() -> str:
    logfile = bootLogPath
    common = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate',
              '--protocol', 'http2', '--logfile', logfile, '--loglevel', 'info']
    if ARGO_AUTH and ARGO_DOMAIN:
        if re.match(r'^[A-Z0-9a-z=]{120,250}$', ARGO_AUTH):
            return json.dumps({'args': common + ['run', '--token', ARGO_AUTH]})
        if 'TunnelSecret' in ARGO_AUTH:
            return json.dumps({'args': common + ['--config',
                                                 os.path.join(runtimeFilePath, 'tunnel.yml'),
                                                 'run']})
    return json.dumps({'args': common + ['--url', f'http://localhost:{ARGO_PORT}']})


def singbox_payload() -> str:
    return json.dumps({'config': sbxConfigPath, 'workingDir': '.', 'disableColor': True})


# ======================== config builders ========================
def build_sbx_config() -> dict:
    return {
        'log': {'disabled': True, 'level': 'error', 'timestamp': True},
        'inbounds': [{
            'type': 'vless',
            'tag': 'vless-argo',
            'listen': '::',
            'listen_port': ARGO_PORT,
            'users': [{'uuid': UUID}],
            'transport': {
                'type': 'ws',
                'path': '/vless-argo',
                'early_data_header_name': 'Sec-WebSocket-Protocol',
            }
        }],
        'outbounds': [{'type': 'direct', 'tag': 'direct'}],
    }


def build_komari_config() -> dict:
    return {
        'endpoint': KOMARI_SERVER,
        'token': KOMARI_TOKEN,
        'interval': KOMARI_INTERVAL,
        'disable_auto_update': True,
        'disable_web_ssh': KOMARI_DISABLE_WEB_SSH,
        'ignore_unsafe_cert': KOMARI_IGNORE_UNSAFE,
    }


# ======================== NativeService (sbx.so / bot.so) ========================
class NativeService:
    def __init__(self, name: str, lib_path: str, start_sym: str, stop_sym: str, payload: str):
        self.name = name
        self.lib_path = lib_path
        self.start_sym = start_sym
        self.stop_sym = stop_sym
        self.payload = payload
        self.lib = None
        self._stop = None
        self._running = False

    def start(self):
        self.lib = ctypes.CDLL(self.lib_path)
        start = getattr(self.lib, self.start_sym)
        start.argtypes = [c_char_p]
        start.restype = c_int
        self._stop = getattr(self.lib, self.stop_sym)
        self._stop.argtypes = []
        self._stop.restype = c_int

        name = self.name
        def _run():
            try:
                rc = start(self.payload.encode('utf-8'))
                if rc != 0:
                    log(f'{name} exited rc={rc}')
            except Exception as e:
                log(f'{name} crashed: {e}')

        threading.Thread(target=_run, daemon=True, name=f'{name}-th').start()
        self._running = True

    def stop(self):
        if not self._running or not self._stop:
            return
        try:
            self._stop()
        except Exception as e:
            log(f'{self.name} stop error: {e}')
        self._running = False


# ======================== KomariAgent ========================
class KomariAgent:
    def __init__(self, lib_path: str):
        self.lib = ctypes.CDLL(lib_path)
        L = self.lib
        L.komari_agent_start_config.argtypes = [c_char_p]
        L.komari_agent_start_config.restype = c_int
        L.komari_agent_start_json.argtypes = [c_char_p]
        L.komari_agent_start_json.restype = c_int
        L.komari_agent_start_env.argtypes = []
        L.komari_agent_start_env.restype = c_int
        L.komari_agent_stop.argtypes = []
        L.komari_agent_stop.restype = c_int
        L.komari_agent_is_running.argtypes = []
        L.komari_agent_is_running.restype = c_int
        L.komari_agent_last_error.argtypes = []
        L.komari_agent_last_error.restype = c_void_p
        L.komari_agent_free_string.argtypes = [c_void_p]
        L.komari_agent_free_string.restype = None
        self._running = False

    def last_error(self) -> str:
        p = self.lib.komari_agent_last_error()
        if not p:
            return ''
        try:
            return ctypes.string_at(p).decode('utf-8', errors='replace')
        finally:
            self.lib.komari_agent_free_string(p)

    def start(self, config_path: str):
        rc = self.lib.komari_agent_start_config(os.fsencode(config_path))
        if rc != 0:
            raise RuntimeError(self.last_error() or f'komari start rc={rc}')
        self._running = True

    def is_running(self) -> bool:
        try:
            return bool(self.lib.komari_agent_is_running())
        except Exception:
            return self._running

    def stop(self):
        try:
            rc = self.lib.komari_agent_stop()
            if rc != 0:
                log(f'komari stop rc={rc}: {self.last_error()}')
        except Exception as e:
            log(f'komari stop error: {e}')
        self._running = False


# ======================== health checks ========================
def wait_port(port: int, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for host, fam in (('127.0.0.1', socket.AF_INET), ('::1', socket.AF_INET6)):
            try:
                with socket.socket(fam, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((host, port)) == 0:
                        return True
            except OSError:
                pass
        time.sleep(0.5)
    return False


def wait_tunnel_ready(timeout: float = 45.0):
    """Return (ok, domain_or_None)."""
    quick = is_quick_tunnel()
    domain_re = re.compile(r'https://([A-Za-z0-9.-]+\.trycloudflare\.com)')
    ok_re = re.compile(
        r'(Registered tunnel connection|Connection [0-9a-fA-F-]+ registered|Updated to new configuration)')
    fatal_re = re.compile(
        r'(Failed to get tunnel|Invalid tunnel|tunnel credentials|Unauthorized|failed to (?:create|connect|register))',
        re.I)

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        content = ''
        try:
            with open(bootLogPath, 'r', errors='replace') as f:
                content = f.read()
        except FileNotFoundError:
            pass

        if fatal_re.search(content):
            log(f'cloudflared fatal log: {content[-300:]}')
            return False, None

        if quick:
            m = domain_re.search(content)
            if m:
                return True, m.group(1)
        else:
            if ok_re.search(content):
                return True, ARGO_DOMAIN
        time.sleep(1)
    return False, None


def wait_komari_running(agent: KomariAgent, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if agent.is_running():
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


# ======================== node link ========================
def build_vless_link(argo_domain: str) -> str:
    if not argo_domain:
        return ''
    isp = get_meta_info()
    node_name = f'{NAME}-{isp}' if NAME else isp
    params = [
        ('encryption', 'none'),
        ('security', 'tls'),
        ('sni', argo_domain),
        ('fp', 'firefox'),
        ('type', 'ws'),
        ('host', argo_domain),
        ('path', '/vless-argo?ed=2048'),
    ]
    qs = '&'.join(f'{k}={quote(str(v), safe="")}' for k, v in params)
    return f'vless://{UUID}@{CFIP}:{CFPORT}?{qs}#{quote(node_name, safe="")}'


# ======================== telegram / merge-sub ========================
def send_telegram(sub_b64: str):
    if not BOT_TOKEN or not CHAT_ID:
        return
    try:
        escaped_name = re.sub(r'([_*\[\]()~`>#+=|{}.!-])', r'\\\1', NAME)
        text = f"**{escaped_name}节点推送通知**\n```{sub_b64}```"
        requests.post(f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage',
                      params={'chat_id': CHAT_ID, 'text': text, 'parse_mode': 'MarkdownV2'},
                      timeout=30)
        log('Telegram sent')
    except Exception as e:
        log(f'Telegram failed: {e}')


def upload_nodes(list_txt: str):
    if not UPLOAD_URL:
        return
    nodes = [l for l in list_txt.split('\n') if l.strip()]
    if not nodes:
        return
    try:
        r = requests.post(f'{UPLOAD_URL}/api/add-nodes',
                          json={'nodes': nodes}, timeout=30)
        if r.status_code == 200:
            log('Nodes uploaded to Merge-sub')
    except Exception as e:
        log(f'Upload nodes failed: {e}')


def delete_old_nodes():
    if not UPLOAD_URL or not os.path.exists(listPath):
        return
    try:
        with open(listPath) as f:
            nodes = [l for l in f.read().split('\n') if l.strip()]
        if not nodes:
            return
        requests.post(f'{UPLOAD_URL}/api/delete-nodes',
                      json={'nodes': nodes}, timeout=30)
        log('Old nodes cleaned')
    except Exception:
        pass


# ======================== HTTP disguise ========================
class WebHandler(BaseHTTPRequestHandler):
    web_path = ''

    def do_GET(self):
        if self.path in ('/', ''):
            if self.web_path and os.path.isfile(self.web_path):
                try:
                    with open(self.web_path, 'rb') as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.send_header('Content-Length', str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                    return
                except Exception:
                    pass
            body = b'Hello world!'
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def log_message(self, *a, **kw):
        pass


def start_http_server(web_file_path: str):
    WebHandler.web_path = web_file_path
    server = HTTPServer(('0.0.0.0', PORT), WebHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True, name='http')
    t.start()
    log(f'HTTP disguise server listening on :{PORT}')
    return server


def resolve_web_file() -> str:
    if not WEB_FILE:
        return ''
    if os.path.isabs(WEB_FILE):
        return WEB_FILE if os.path.isfile(WEB_FILE) else ''
    p = os.path.join(ROOT, WEB_FILE)
    return p if os.path.isfile(p) else ''


# ======================== start / stop services ========================
def start_all_services(state: dict) -> list:
    services = []

    # ---- sing-box ----
    log('Starting sing-box ...')
    sbx = NativeService('sing-box',
                        state['sbx_lib'],
                        'StartSingBox', 'StopSingBox',
                        singbox_payload())
    sbx.start()
    services.append(sbx)
    if not wait_port(ARGO_PORT, timeout=20):
        raise RuntimeError(f'sing-box not listening on :{ARGO_PORT}')
    log('sing-box is up')

    # ---- cloudflared ----
    if DISABLE_ARGO:
        log('DISABLE_ARGO, skipping cloudflared')
        state['argo_domain'] = ''
    else:
        log('Starting cloudflared ...')
        cf = NativeService('cloudflared',
                           state['cf_lib'],
                           'StartCloudflared', 'StopCloudflared',
                           cloudflared_payload())
        cf.start()
        services.append(cf)
        ok, domain = wait_tunnel_ready(timeout=45)
        if not ok:
            raise RuntimeError('cloudflared tunnel not ready')
        state['argo_domain'] = domain or ''
        log(f'cloudflared is up, domain={state["argo_domain"]}')

    # ---- komari ----
    if NEED_KOMARI:
        log('Starting komari agent ...')
        try:
            km = KomariAgent(state['komari_lib'])
            km.start(komariConfigPath)
            if not wait_komari_running(km, timeout=10):
                raise RuntimeError('komari agent not running after start')
            services.append(km)
            log('komari is up')
        except Exception as e:
            log(f'komari start error: {e}')
            raise
    else:
        log('KOMARI_SERVER / KOMARI_TOKEN missing, skipping komari')

    return services


def stop_all_services(services):
    for s in reversed(services):
        try:
            s.stop()
        except Exception:
            pass


# ======================== main ========================
def main():
    # 0) preflight
    os.makedirs(runtimeFilePath, exist_ok=True)
    acquire_pid_lock()

    # 1) purge stale ports
    if not free_port(ARGO_PORT):
        log(f'FATAL: cannot free port {ARGO_PORT}')
        release_pid_lock(); sys.exit(1)
    if not free_port(PORT):
        log(f'FATAL: cannot free port {PORT}')
        release_pid_lock(); sys.exit(1)

    # 2) delete previous nodes in merge-sub (before wiping list.txt)
    delete_old_nodes()

    # 3) clear runtime configs (keep .so)
    clear_before_startup()

    # 4) downloads (with 3x retry)
    base = f'https://{ARCH}.oooen.com'
    try:
        sbx_lib = download_with_retry(f'{base}/sbx.so', 'sbx.so', attempts=3)
        cf_lib  = download_with_retry(f'{base}/bot.so', 'bot.so', attempts=3) if not DISABLE_ARGO else ''
        km_lib  = ''
        if NEED_KOMARI:
            km_url = f'https://gitlab.com/minono/komari-agent-so/-/releases/v0.0.1/downloads/kma-{ARCH}.so'
            km_lib = download_with_retry(km_url, f'kma-{ARCH}.so', attempts=3)
    except Exception as e:
        log(f'FATAL: download failed after retries: {e}')
        release_pid_lock(); sys.exit(1)

    # 5) write configs
    with open(sbxConfigPath, 'w') as f:
        json.dump(build_sbx_config(), f, indent=2)
    if NEED_KOMARI:
        with open(komariConfigPath, 'w') as f:
            json.dump(build_komari_config(), f, indent=2)

    # 6) prepare tunnel yml
    argo_type_write()

    state = {
        'sbx_lib': sbx_lib,
        'cf_lib': cf_lib,
        'komari_lib': km_lib,
        'argo_domain': '',
    }

    # 7) startup with full retry
    services, last_err = None, None
    for attempt in range(1, STARTUP_RETRIES + 1):
        try:
            log(f'--- startup attempt {attempt}/{STARTUP_RETRIES} ---')
            services = start_all_services(state)
            last_err = None
            break
        except Exception as e:
            last_err = e
            log(f'attempt {attempt} failed: {e}')
            if services:
                stop_all_services(services)
            services = None
            # 只清理配置,不动 so
            for f in (sbxConfigPath, komariConfigPath, bootLogPath):
                _rm(f)
            if attempt < STARTUP_RETRIES:
                time.sleep(5)

    if services is None:
        log(f'FATAL: all {STARTUP_RETRIES} startup attempts failed: {last_err}')
        release_pid_lock()
        sys.exit(1)

    # 8) generate vless link
    argo_domain = state.get('argo_domain', '')
    link = build_vless_link(argo_domain)
    sub_b64 = base64.b64encode(link.encode()).decode() if link else ''
    if sub_b64:
        with open(subPath, 'w') as f:
            f.write(sub_b64)
        with open(listPath, 'w') as f:
            f.write(link)
        log('\033[32m' + sub_b64 + '\033[0m')
        log('\033[35mLogs will be cleared in 90 seconds.\033[0m')
        send_telegram(sub_b64)
        upload_nodes(link)
    else:
        log('No argo domain available (DISABLE_ARGO ?), no node generated')

    # 9) disguise web server
    web_file = resolve_web_file()
    http_server = start_http_server(web_file)

    # 10) signals
    def _shutdown(*_):
        log('Shutting down ...')
        stop_all_services(services)
        try: http_server.shutdown()
        except Exception: pass
        release_pid_lock()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # 11) delayed cleanup
    def _later():
        time.sleep(CLEANUP_DELAY_SEC)
        clear_after_startup()
        os.system('clear' if os.name == 'posix' else 'cls')
        log('App is running')

    threading.Thread(target=_later, daemon=True).start()

    # 12) hold
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _shutdown()


if __name__ == '__main__':
    main()
