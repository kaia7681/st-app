#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sbx-native (streamlit build)
    streamlit run app.py --server.port=3000 --server.address=0.0.0.0
"""

import os, sys, time, json, re, base64, hashlib, shutil, socket, atexit
import subprocess, threading, ctypes
from ctypes import c_int, c_char_p, c_void_p
from urllib.parse import quote

try:
    import requests
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "requests"])
    import requests

import streamlit as st


# ======================== ENV ========================
UPLOAD_URL        = os.environ.get('UPLOAD_URL', '')
UUID              = os.environ.get('UUID', '0a6568ff-ea3c-4271-9020-450560e10d63')
ARGO_PORT         = int(os.environ.get('ARGO_PORT', '8001'))
ARGO_DOMAIN       = os.environ.get('ARGO_DOMAIN', '')
ARGO_AUTH         = os.environ.get('ARGO_AUTH', '')
CFIP              = os.environ.get('CFIP', 'spring.io')
CFPORT            = int(os.environ.get('CFPORT', '443'))
NAME              = os.environ.get('NAME', 'Stream')
CHAT_ID           = os.environ.get('CHAT_ID', '')
BOT_TOKEN         = os.environ.get('BOT_TOKEN', '')
FILE_PATH         = os.environ.get('FILE_PATH', '.cache')
WEB_FILE          = os.environ.get('WEB_FILE', 'cherrystudio.html')
DISABLE_ARGO      = os.environ.get('DISABLE_ARGO', 'false').lower() in ('true', 'yes')
SHOW_LOG          = os.environ.get('SHOW_LOG', 'true').lower() not in ('false', 'disable', 'no')

KOMARI_SERVER           = os.environ.get('KOMARI_SERVER', '')
KOMARI_TOKEN            = os.environ.get('KOMARI_TOKEN', '')
KOMARI_INTERVAL         = int(os.environ.get('KOMARI_INTERVAL', '15'))
KOMARI_DISABLE_WEB_SSH  = os.environ.get('KOMARI_DISABLE_WEB_SSH', 'false').lower() in ('true', 'yes')
KOMARI_IGNORE_UNSAFE    = os.environ.get('KOMARI_IGNORE_UNSAFE_CERT', 'false').lower() in ('true', 'yes')

NO_CLEANUP        = os.environ.get('NO_CLEANUP', 'false').lower() in ('true', 'yes')
SHOW_SUB_UI       = os.environ.get('SHOW_SUB_UI', 'false').lower() in ('true', 'yes')

NEED_KOMARI       = bool(KOMARI_SERVER and KOMARI_TOKEN)
STARTUP_RETRIES   = 3
CLEANUP_DELAY_SEC = 90


# ======================== paths / helpers ========================
def log(*a, **kw):
    if SHOW_LOG:
        print('[sbx]', *a, **kw, flush=True)


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


def get_meta_info() -> str:
    for url, ck, ok, org in (
        ('https://api.ip.sb/geoip', 'country_code', None, 'isp'),
        ('http://ip-api.com/json', 'countryCode', 'status', 'org'),
    ):
        try:
            r = requests.get(url, timeout=3)
            if r.status_code != 200:
                continue
            d = r.json()
            if ok and d.get(ok) != 'success':
                continue
            if d.get(ck) and d.get(org):
                return f"{d[ck]}-{d[org]}".replace(' ', '_')
        except Exception:
            pass
    return 'Unknown'


def _rm(path):
    try:
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        elif os.path.exists(path):
            os.unlink(path)
    except Exception:
        pass


def clear_dir(keep: set):
    if not os.path.isdir(runtimeFilePath):
        return
    for f in os.listdir(runtimeFilePath):
        if f in keep:
            continue
        _rm(os.path.join(runtimeFilePath, f))


def clear_before_startup():
    keep = {'app.pid'}
    if os.path.isdir(runtimeFilePath):
        for f in os.listdir(runtimeFilePath):
            if f.endswith('.so'):
                keep.add(f)
    clear_dir(keep)


def clear_after_startup():
    if NO_CLEANUP:
        log('NO_CLEANUP=true, skipping post-cleanup')
        return
    clear_dir({'sub.txt', 'list.txt', 'app.pid'})


# ======================== pid lock / port ========================
def acquire_pid_lock():
    os.makedirs(runtimeFilePath, exist_ok=True)
    if os.path.exists(pidLockPath):
        try:
            old = int(open(pidLockPath).read().strip())
            if old != os.getpid():
                os.kill(old, 0)
                try:
                    with open(f'/proc/{old}/cmdline', 'rb') as f:
                        cmd = f.read()
                    if b'streamlit' in cmd or b'app.py' in cmd:
                        log(f'Killing stale {old}')
                        os.kill(old, 9)
                        time.sleep(1)
                except FileNotFoundError:
                    pass
        except Exception:
            pass
    with open(pidLockPath, 'w') as f:
        f.write(str(os.getpid()))


def release_pid_lock():
    try:
        if os.path.exists(pidLockPath):
            if open(pidLockPath).read().strip() == str(os.getpid()):
                os.unlink(pidLockPath)
    except Exception:
        pass


def _port_in_use(port: int) -> bool:
    for host, fam in (('127.0.0.1', socket.AF_INET), ('::1', socket.AF_INET6)):
        try:
            with socket.socket(fam, socket.SOCK_STREAM) as s:
                s.settimeout(0.4)
                if s.connect_ex((host, port)) == 0:
                    return True
        except OSError:
            pass
    return False


def free_port(port: int, timeout: float = 10.0) -> bool:
    if not _port_in_use(port):
        return True
    log(f'Free port {port} ...')
    for tool in (['lsof', '-ti', f':{port}'], ['fuser', '-k', f'{port}/tcp']):
        try:
            r = subprocess.run(tool, capture_output=True, text=True, timeout=5)
            for pid in r.stdout.split():
                if pid.isdigit() and int(pid) != os.getpid():
                    try: os.kill(int(pid), 15)
                    except ProcessLookupError: pass
        except FileNotFoundError:
            continue
        except Exception:
            pass
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _port_in_use(port):
            return True
        time.sleep(0.5)
    try:
        r = subprocess.run(['lsof', '-ti', f':{port}'], capture_output=True, text=True, timeout=5)
        for pid in r.stdout.split():
            if pid.isdigit() and int(pid) != os.getpid():
                try: os.kill(int(pid), 9)
                except ProcessLookupError: pass
    except Exception:
        pass
    time.sleep(1)
    return not _port_in_use(port)


# ======================== download ========================
def download_library(url: str, filename: str) -> str:
    target = os.path.join(runtimeFilePath, filename)
    os.makedirs(runtimeFilePath, exist_ok=True)
    if os.path.exists(target):
        with open(target, 'rb') as f:
            if f.read(4) == b'\x7fELF':
                log(f'Using cached {target}')
                return target
    tmp = target + '.download'
    try:
        log(f'Downloading {url}')
        r = requests.get(url, stream=True, timeout=180, allow_redirects=True)
        r.raise_for_status()
        with open(tmp, 'wb') as f:
            for ch in r.iter_content(8192):
                if ch:
                    f.write(ch)
        with open(tmp, 'rb') as f:
            if f.read(4) != b'\x7fELF':
                raise RuntimeError(f'{filename}: not ELF')
        os.replace(tmp, target)
        os.chmod(target, 0o755)
        return target
    finally:
        if os.path.exists(tmp):
            _rm(tmp)


def download_with_retry(url: str, filename: str, attempts: int = 3) -> str:
    last = None
    for i in range(attempts):
        try:
            return download_library(url, filename)
        except Exception as e:
            last = e
            log(f'Download {filename} attempt {i+1}/{attempts} failed: {e}')
            if i + 1 < attempts:
                time.sleep(2 * (i + 1))
    raise last


# ======================== argo / payloads ========================
def argo_type_write():
    if not (ARGO_AUTH and ARGO_DOMAIN):
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
    common = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate',
              '--protocol', 'http2', '--logfile', bootLogPath, '--loglevel', 'info']
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


# ======================== NativeService ========================
class NativeService:
    def __init__(self, name, lib_path, start_sym, stop_sym, payload):
        self.name, self.lib_path = name, lib_path
        self.start_sym, self.stop_sym, self.payload = start_sym, stop_sym, payload
        self._stop = None
        self._running = False

    def start(self):
        lib = ctypes.CDLL(self.lib_path)
        start = getattr(lib, self.start_sym)
        start.argtypes = [c_char_p]; start.restype = c_int
        self._stop = getattr(lib, self.stop_sym)
        self._stop.argtypes = []; self._stop.restype = c_int
        self._lib = lib
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
        try: self._stop()
        except Exception as e: log(f'{self.name} stop err: {e}')
        self._running = False


# ======================== KomariAgent ========================
class KomariAgent:
    def __init__(self, lib_path):
        self.lib = ctypes.CDLL(lib_path)
        L = self.lib
        L.komari_agent_start_config.argtypes = [c_char_p]; L.komari_agent_start_config.restype = c_int
        L.komari_agent_start_json.argtypes   = [c_char_p]; L.komari_agent_start_json.restype   = c_int
        L.komari_agent_start_env.argtypes    = [];         L.komari_agent_start_env.restype    = c_int
        L.komari_agent_stop.argtypes         = [];         L.komari_agent_stop.restype         = c_int
        L.komari_agent_is_running.argtypes   = [];         L.komari_agent_is_running.restype   = c_int
        L.komari_agent_last_error.argtypes   = [];         L.komari_agent_last_error.restype   = c_void_p
        L.komari_agent_free_string.argtypes  = [c_void_p]; L.komari_agent_free_string.restype  = None
        self._running = False

    def last_error(self) -> str:
        p = self.lib.komari_agent_last_error()
        if not p: return ''
        try: return ctypes.string_at(p).decode('utf-8', errors='replace')
        finally: self.lib.komari_agent_free_string(p)

    def start(self, cfg):
        rc = self.lib.komari_agent_start_config(os.fsencode(cfg))
        if rc != 0:
            raise RuntimeError(self.last_error() or f'komari rc={rc}')
        self._running = True

    def is_running(self) -> bool:
        try: return bool(self.lib.komari_agent_is_running())
        except Exception: return self._running

    def stop(self):
        try:
            rc = self.lib.komari_agent_stop()
            if rc != 0: log(f'komari stop rc={rc}: {self.last_error()}')
        except Exception as e: log(f'komari stop err: {e}')
        self._running = False


# ======================== waits ========================
def wait_port(port, timeout=20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for host, fam in (('127.0.0.1', socket.AF_INET), ('::1', socket.AF_INET6)):
            try:
                with socket.socket(fam, socket.SOCK_STREAM) as s:
                    s.settimeout(0.4)
                    if s.connect_ex((host, port)) == 0:
                        return True
            except OSError:
                pass
        time.sleep(0.5)
    return False


def wait_tunnel_ready(timeout=45.0):
    quick = is_quick_tunnel()
    domain_re = re.compile(r'https://([A-Za-z0-9.-]+\.trycloudflare\.com)')
    ok_re     = re.compile(r'(Registered tunnel connection|Connection [0-9a-fA-F-]+ registered|Updated to new configuration)')
    fatal_re  = re.compile(r'(Failed to get tunnel|Invalid tunnel|tunnel credentials|Unauthorized|failed to (?:create|connect|register))', re.I)
    deadline = time.monotonic() + timeout
    content = ''
    while time.monotonic() < deadline:
        try:
            with open(bootLogPath, 'r', errors='replace') as f:
                content = f.read()
        except FileNotFoundError:
            pass
        if fatal_re.search(content):
            log(f'cf fatal: {content[-300:]}')
            return False, None
        if quick:
            m = domain_re.search(content)
            if m: return True, m.group(1)
        else:
            if ok_re.search(content):
                return True, ARGO_DOMAIN
        time.sleep(1)
    return False, None


def wait_komari_running(agent, timeout=10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if agent.is_running(): return True
        except Exception: pass
        time.sleep(0.5)
    return False


# ======================== link ========================
def build_vless_link(argo_domain: str) -> str:
    if not argo_domain: return ''
    isp = get_meta_info()
    node_name = f'{NAME}-{isp}' if NAME else isp
    params = [
        ('encryption', 'none'), ('security', 'tls'),
        ('sni', argo_domain), ('fp', 'firefox'),
        ('type', 'ws'), ('host', argo_domain),
        ('path', '/vless-argo?ed=2048'),
    ]
    qs = '&'.join(f'{k}={quote(str(v), safe="")}' for k, v in params)
    return f'vless://{UUID}@{CFIP}:{CFPORT}?{qs}#{quote(node_name, safe="")}'


# ======================== tg / merge-sub ========================
def send_telegram(sub_b64):
    if not BOT_TOKEN or not CHAT_ID: return
    try:
        name = re.sub(r'([_*\[\]()~`>#+=|{}.!-])', r'\\\1', NAME)
        requests.post(f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage',
                      params={'chat_id': CHAT_ID,
                              'text': f'**{name}节点推送**\n```{sub_b64}```',
                              'parse_mode': 'MarkdownV2'},
                      timeout=30)
    except Exception as e: log(f'tg fail: {e}')


def upload_nodes(list_txt):
    if not UPLOAD_URL: return
    nodes = [l for l in list_txt.split('\n') if l.strip()]
    if not nodes: return
    try:
        r = requests.post(f'{UPLOAD_URL}/api/add-nodes',
                          json={'nodes': nodes}, timeout=30)
        if r.status_code == 200: log('Uploaded to Merge-sub')
    except Exception as e: log(f'upload fail: {e}')


def delete_old_nodes():
    if not UPLOAD_URL or not os.path.exists(listPath): return
    try:
        nodes = [l for l in open(listPath) .read().split('\n') if l.strip()]
        if nodes:
            requests.post(f'{UPLOAD_URL}/api/delete-nodes',
                          json={'nodes': nodes}, timeout=30)
    except Exception:
        pass


# ======================== start services ========================
def start_all_services(state: dict) -> list:
    services = []

    log('Starting sing-box ...')
    sbx = NativeService('sing-box', state['sbx_lib'],
                        'StartSingBox', 'StopSingBox', singbox_payload())
    sbx.start(); services.append(sbx)
    if not wait_port(ARGO_PORT, 20):
        raise RuntimeError(f'sing-box not listening on :{ARGO_PORT}')
    log('sing-box up')

    if DISABLE_ARGO:
        state['argo_domain'] = ''
    else:
        log('Starting cloudflared ...')
        cf = NativeService('cloudflared', state['cf_lib'],
                           'StartCloudflared', 'StopCloudflared', cloudflared_payload())
        cf.start(); services.append(cf)
        ok, domain = wait_tunnel_ready(45)
        if not ok:
            raise RuntimeError('cloudflared tunnel not ready')
        state['argo_domain'] = domain or ''
        log(f'cloudflared up, domain={state["argo_domain"]}')

    if NEED_KOMARI:
        log('Starting komari ...')
        try:
            km = KomariAgent(state['komari_lib'])
            km.start(komariConfigPath)
            if not wait_komari_running(km, 10):
                raise RuntimeError('komari not running')
            services.append(km)
            log('komari up')
        except Exception as e:
            log(f'komari err: {e}')
            raise
    return services


def stop_all_services(services):
    for s in reversed(services):
        try: s.stop()
        except Exception: pass


# ======================== bootstrap (只跑一次) ========================
@st.cache_resource(show_spinner=False)
def bootstrap() -> dict:
    result = {'ok': False, 'err': '', 'services': [], 'sub_b64': '',
              'link': '', 'argo_domain': ''}

    try:
        os.makedirs(runtimeFilePath, exist_ok=True)

        if not free_port(ARGO_PORT):
            raise RuntimeError(f'cannot free port {ARGO_PORT}')

        delete_old_nodes()
        acquire_pid_lock()
        clear_before_startup()

        base = f'https://{ARCH}.oooen.com'
        sbx_lib = download_with_retry(f'{base}/sbx.so', 'sbx.so', 3)
        cf_lib = ''
        if not DISABLE_ARGO:
            cf_lib = download_with_retry(f'{base}/bot.so', 'bot.so', 3)
        km_lib = ''
        if NEED_KOMARI:
            km_url = f'https://gitlab.com/minono/komari-agent-so/-/releases/v0.0.1/downloads/kma-{ARCH}.so'
            km_lib = download_with_retry(km_url, f'kma-{ARCH}.so', 3)

        with open(sbxConfigPath, 'w') as f:
            json.dump(build_sbx_config(), f, indent=2)
        if NEED_KOMARI:
            with open(komariConfigPath, 'w') as f:
                json.dump(build_komari_config(), f, indent=2)

        argo_type_write()

        state = {'sbx_lib': sbx_lib, 'cf_lib': cf_lib,
                 'komari_lib': km_lib, 'argo_domain': ''}

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
                for f in (sbxConfigPath, komariConfigPath, bootLogPath):
                    _rm(f)
                if attempt < STARTUP_RETRIES:
                    time.sleep(5)

        if services is None:
            raise RuntimeError(f'all {STARTUP_RETRIES} attempts failed: {last_err}')

        # 节点生成
        argo_domain = state.get('argo_domain', '')
        link = build_vless_link(argo_domain)
        sub_b64 = base64.b64encode(link.encode()).decode() if link else ''
        if sub_b64:
            with open(subPath, 'w') as f:
                f.write(sub_b64)
            with open(listPath, 'w') as f:
                f.write(link)
            log('SUB_B64: ' + sub_b64)
            send_telegram(sub_b64)
            upload_nodes(link)

        # 退出钩子
        def _atexit():
            log('atexit: stopping services')
            stop_all_services(services)
            release_pid_lock()
        atexit.register(_atexit)

        # 90s 延时清理
        def _later():
            time.sleep(CLEANUP_DELAY_SEC)
            clear_after_startup()
            log('90s cleanup done')
        threading.Thread(target=_later, daemon=True, name='cleanup').start()

        result.update({
            'ok': True, 'services': services, 'sub_b64': sub_b64,
            'link': link, 'argo_domain': argo_domain,
        })
    except Exception as e:
        result['err'] = str(e)
        log(f'Bootstrap FATAL: {e}')
    return result


# ======================== 页面渲染 ========================
st.set_page_config(page_title='Demo', page_icon='🌐', layout='centered')
st.markdown(
    """
    <style>
    #MainMenu, header, footer { visibility: hidden; }
    .block-container { padding-top: 1rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

state = bootstrap()

if not state['ok']:
    st.error('Service is unavailable. Please try again later.')
    st.caption(f'({state["err"]})')
else:
    # 伪装页:优先使用 index.html / WEB_FILE
    web_file = WEB_FILE if os.path.isabs(WEB_FILE) else os.path.join(ROOT, WEB_FILE)
    rendered = False
    if web_file and os.path.isfile(web_file):
        try:
            with open(web_file, encoding='utf-8') as f:
                html = f.read()
            st.markdown(html, unsafe_allow_html=True)
            rendered = True
        except Exception as e:
            log(f'read {web_file} failed: {e}')
    if not rendered:
        st.title('Hello world!')
        st.write('This service is running normally.')

    # 可选:UI 里展示订阅(默认关闭)
    if SHOW_SUB_UI and state['sub_b64']:
        with st.expander('Subscription (internal)', expanded=False):
            st.code(state['link'], language='text')
            st.text_input('base64', value=state['sub_b64'], label_visibility='collapsed')
            st.caption(f'argo domain: {state["argo_domain"]}')
