#!/usr/bin/env python3
"""
CTI Hub — Backend v2
====================
Features:
  - JWT-based authentication
  - Dynamic CTI engine management (add/remove any engine)
  - User management (admin creates analyst accounts)
  - CAPA integration (optional, toggle on/off)
  - Elasticsearch result shipping (optional)
  - Docker-ready

First run: visit /setup to create the admin account.

Install:
    pip install flask flask-cors requests pyjwt bcrypt

Run:
    python3 backend.py

Docker:
    docker compose up -d
"""

import os, json, time, hashlib, tempfile, subprocess, datetime, secrets
from pathlib import Path
from functools import wraps

import requests
import bcrypt
import jwt
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='static')
CORS(app, supports_credentials=True)

# ── Paths ────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
CONFIG_FILE = BASE_DIR / 'config.json'
USERS_FILE  = BASE_DIR / 'users.json'
CACHE_DIR   = Path(os.environ.get('CAPA_CACHE', BASE_DIR / 'capa_cache'))
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# ── JWT secret (generated once, persisted) ───────────────────────
SECRET_FILE = BASE_DIR / '.jwt_secret'
if not SECRET_FILE.exists():
    SECRET_FILE.write_text(secrets.token_hex(32))
JWT_SECRET  = SECRET_FILE.read_text().strip()
JWT_EXPIRY  = 60 * 60 * 8  # 8 hours

# ── Default config structure ─────────────────────────────────────
DEFAULT_CONFIG = {
    "engines": [
        {
            "id": "virustotal",
            "name": "VirusTotal",
            "icon": "🔬",
            "enabled": True,
            "api_key": "",
            "docs_url": "https://www.virustotal.com/gui/join-us",
            "free_tier": "4 req/min",
            "supports": ["hash", "ip", "url", "domain"]
        },
        {
            "id": "abuseipdb",
            "name": "AbuseIPDB",
            "icon": "🛡",
            "enabled": True,
            "api_key": "",
            "docs_url": "https://www.abuseipdb.com/register",
            "free_tier": "1,000 req/day",
            "supports": ["ip"]
        },
        {
            "id": "shodan",
            "name": "Shodan",
            "icon": "🌐",
            "enabled": True,
            "api_key": "",
            "docs_url": "https://account.shodan.io/register",
            "free_tier": "100 credits/month",
            "supports": ["ip"]
        },
        {
            "id": "otx",
            "name": "OTX AlienVault",
            "icon": "👽",
            "enabled": True,
            "api_key": "",
            "docs_url": "https://otx.alienvault.com/",
            "free_tier": "Unlimited",
            "supports": ["hash", "ip", "url", "domain"]
        },
        {
            "id": "urlscan",
            "name": "URLScan.io",
            "icon": "🔗",
            "enabled": True,
            "api_key": "",
            "docs_url": "https://urlscan.io/user/signup",
            "free_tier": "100 scans/day",
            "supports": ["url", "domain"]
        },
        {
            "id": "greynoise",
            "name": "GreyNoise",
            "icon": "📡",
            "enabled": True,
            "api_key": "",
            "docs_url": "https://www.greynoise.io/plans/community",
            "free_tier": "100 IPs/day",
            "supports": ["ip"]
        },
        {
            "id": "malwarebazaar",
            "name": "MalwareBazaar",
            "icon": "🦠",
            "enabled": True,
            "api_key": "",
            "docs_url": "https://bazaar.abuse.ch/api/",
            "free_tier": "Free",
            "supports": ["hash"]
        },
        {
            "id": "threatfox",
            "name": "ThreatFox",
            "icon": "🦊",
            "enabled": True,
            "api_key": "",
            "docs_url": "https://threatfox.abuse.ch/api/",
            "free_tier": "Free",
            "supports": ["hash", "ip", "url", "domain"]
        },
        {
            "id": "hybridanalysis",
            "name": "Hybrid Analysis",
            "icon": "⚗",
            "enabled": False,
            "api_key": "",
            "docs_url": "https://www.hybrid-analysis.com/signup",
            "free_tier": "200 req/day (requires vetting)",
            "supports": ["hash"]
        }
    ],
    "capa": {
        "enabled": False,
        "binary_path": "/usr/local/bin/capa"
    },
    "elasticsearch": {
        "enabled": False,
        "url": "https://localhost:9200",
        "username": "elastic",
        "password": "",
        "index": "cti-scans",
        "verify_ssl": False
    },
    "settings": {
        "app_name": "CTI Hub",
        "mfa_enabled": False,
        "session_timeout": 480
    }
}


# ── Config helpers ───────────────────────────────────────────────
def load_config() -> dict:
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return DEFAULT_CONFIG.copy()


def save_config(cfg: dict):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def get_engine(engine_id: str) -> dict | None:
    cfg = load_config()
    return next((e for e in cfg['engines'] if e['id'] == engine_id), None)


def get_key(engine_id: str) -> str:
    e = get_engine(engine_id)
    return e.get('api_key', '') if e else ''


# ── User helpers ─────────────────────────────────────────────────
def load_users() -> dict:
    if not USERS_FILE.exists():
        return {}
    try:
        return json.loads(USERS_FILE.read_text())
    except Exception:
        return {}


def save_users(users: dict):
    USERS_FILE.write_text(json.dumps(users, indent=2))


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


# ── JWT helpers ──────────────────────────────────────────────────
def create_token(username: str, role: str) -> str:
    payload = {
        'sub':  username,
        'role': role,
        'exp':  datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXPIRY),
        'iat':  datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_current_user():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        token = auth[7:]
    else:
        token = request.cookies.get('cti_token', '')
    return decode_token(token)


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
        if user.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated


# ── Response builder ─────────────────────────────────────────────
def resp(status, rows, score=None, link=None, techniques=None):
    d = {'status': status, 'rows': rows}
    if score      is not None: d['score']     = score
    if link:                   d['link']       = link
    if techniques:             d['techniques'] = techniques
    return jsonify(d)


def no_key(tool_name):
    return resp('error', [
        ['Config',  f'{tool_name} key not configured'],
        ['Fix',     'Go to Admin → API Management to add your key'],
    ])


def engine_disabled(tool_name):
    return resp('error', [
        ['Status', f'{tool_name} is disabled'],
        ['Fix',    'Go to Admin → API Management to enable it'],
    ])


# ══════════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════════════════════════

@app.route('/api/auth/setup-status')
def setup_status():
    """Check if initial setup is needed."""
    users = load_users()
    return jsonify({'needs_setup': len(users) == 0})


@app.route('/api/auth/setup', methods=['POST'])
def setup():
    """Create the first admin account."""
    users = load_users()
    if users:
        return jsonify({'error': 'Setup already completed'}), 400

    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    users[username] = {
        'password': hash_password(password),
        'role':     'admin',
        'created':  datetime.datetime.utcnow().isoformat(),
    }
    save_users(users)
    token = create_token(username, 'admin')
    return jsonify({'token': token, 'username': username, 'role': 'admin'})


@app.route('/api/auth/login', methods=['POST'])
def login():
    data     = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    users = load_users()
    if not users:
        return jsonify({'error': 'No users configured. Visit /setup'}), 401

    user = users.get(username)
    if not user or not check_password(password, user['password']):
        return jsonify({'error': 'Invalid username or password'}), 401

    token = create_token(username, user['role'])
    return jsonify({
        'token':    token,
        'username': username,
        'role':     user['role'],
    })


@app.route('/api/auth/me')
@require_auth
def me():
    user = get_current_user()
    return jsonify({'username': user['sub'], 'role': user['role']})


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    return jsonify({'status': 'ok'})


# ══════════════════════════════════════════════════════════════════
#  USER MANAGEMENT (admin only)
# ══════════════════════════════════════════════════════════════════

@app.route('/api/users', methods=['GET'])
@require_admin
def list_users():
    users = load_users()
    return jsonify([
        {'username': u, 'role': d['role'], 'created': d.get('created', '')}
        for u, d in users.items()
    ])


@app.route('/api/users', methods=['POST'])
@require_admin
def create_user():
    data     = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role     = data.get('role', 'analyst')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if role not in ('admin', 'analyst'):
        return jsonify({'error': 'Role must be admin or analyst'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    users = load_users()
    if username in users:
        return jsonify({'error': 'Username already exists'}), 400

    users[username] = {
        'password': hash_password(password),
        'role':     role,
        'created':  datetime.datetime.utcnow().isoformat(),
    }
    save_users(users)
    return jsonify({'status': 'ok', 'username': username, 'role': role})


@app.route('/api/users/<username>', methods=['DELETE'])
@require_admin
def delete_user(username):
    current = get_current_user()
    if current['sub'] == username:
        return jsonify({'error': 'Cannot delete your own account'}), 400

    users = load_users()
    if username not in users:
        return jsonify({'error': 'User not found'}), 404

    del users[username]
    save_users(users)
    return jsonify({'status': 'ok'})


@app.route('/api/users/<username>/password', methods=['PUT'])
@require_admin
def change_password(username):
    data     = request.json or {}
    password = data.get('password', '')
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    users = load_users()
    if username not in users:
        return jsonify({'error': 'User not found'}), 404

    users[username]['password'] = hash_password(password)
    save_users(users)
    return jsonify({'status': 'ok'})


# ══════════════════════════════════════════════════════════════════
#  ENGINE MANAGEMENT (admin only)
# ══════════════════════════════════════════════════════════════════

@app.route('/api/engines', methods=['GET'])
@require_auth
def list_engines():
    cfg     = load_config()
    engines = cfg.get('engines', [])
    user    = get_current_user()
    # Analysts see engines but not the actual keys
    result  = []
    for e in engines:
        entry = {k: v for k, v in e.items() if k != 'api_key'}
        if user['role'] == 'admin':
            entry['has_key'] = bool(e.get('api_key'))
        result.append(entry)
    return jsonify(result)


@app.route('/api/engines', methods=['POST'])
@require_admin
def add_engine():
    data = request.json or {}
    required = ['id', 'name', 'supports']
    for f in required:
        if not data.get(f):
            return jsonify({'error': f'{f} is required'}), 400

    cfg     = load_config()
    engines = cfg.get('engines', [])

    if any(e['id'] == data['id'] for e in engines):
        return jsonify({'error': 'Engine ID already exists'}), 400

    engines.append({
        'id':        data['id'],
        'name':      data['name'],
        'icon':      data.get('icon', '🔌'),
        'enabled':   data.get('enabled', False),
        'api_key':   data.get('api_key', ''),
        'docs_url':  data.get('docs_url', ''),
        'free_tier': data.get('free_tier', ''),
        'supports':  data['supports'],
        'custom':    True,
    })
    cfg['engines'] = engines
    save_config(cfg)
    return jsonify({'status': 'ok'})


@app.route('/api/engines/<engine_id>', methods=['PUT'])
@require_admin
def update_engine(engine_id):
    data    = request.json or {}
    cfg     = load_config()
    engines = cfg.get('engines', [])

    for i, e in enumerate(engines):
        if e['id'] == engine_id:
            if 'api_key' in data:   engines[i]['api_key']   = data['api_key']
            if 'enabled' in data:   engines[i]['enabled']   = data['enabled']
            if 'name'    in data:   engines[i]['name']      = data['name']
            if 'docs_url' in data:  engines[i]['docs_url']  = data['docs_url']
            if 'free_tier' in data: engines[i]['free_tier'] = data['free_tier']
            if 'supports' in data:  engines[i]['supports']  = data['supports']
            cfg['engines'] = engines
            save_config(cfg)
            return jsonify({'status': 'ok'})

    return jsonify({'error': 'Engine not found'}), 404


@app.route('/api/engines/<engine_id>', methods=['DELETE'])
@require_admin
def delete_engine(engine_id):
    cfg     = load_config()
    engines = cfg.get('engines', [])
    engine  = next((e for e in engines if e['id'] == engine_id), None)

    if not engine:
        return jsonify({'error': 'Engine not found'}), 404
    if not engine.get('custom'):
        return jsonify({'error': 'Cannot delete built-in engines. Disable them instead.'}), 400

    cfg['engines'] = [e for e in engines if e['id'] != engine_id]
    save_config(cfg)
    return jsonify({'status': 'ok'})


@app.route('/api/engines/<engine_id>/test', methods=['POST'])
@require_admin
def test_engine(engine_id):
    engine = get_engine(engine_id)
    if not engine:
        return jsonify({'error': 'Engine not found'}), 404
    if not engine.get('api_key'):
        return jsonify({'status': 'no_key', 'message': 'No API key configured'})

    # Quick connectivity test using a known safe value
    test_values = {
        'ip':     '8.8.8.8',
        'hash':   '44d88612fea8a8f36de82e1278abb02f',  # EICAR MD5
        'url':    'https://google.com',
        'domain': 'google.com',
    }
    test_type  = engine['supports'][0] if engine.get('supports') else 'ip'
    test_value = test_values.get(test_type, '8.8.8.8')

    try:
        result = run_builtin_engine(engine_id, test_value, test_type)
        return jsonify({'status': 'ok', 'message': f'Connected successfully. Test: {test_value}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)[:100]})


# ══════════════════════════════════════════════════════════════════
#  CAPA CONFIG (admin only)
# ══════════════════════════════════════════════════════════════════

@app.route('/api/capa/config', methods=['GET'])
@require_admin
def get_capa_config():
    cfg = load_config()
    return jsonify(cfg.get('capa', {}))


@app.route('/api/capa/config', methods=['PUT'])
@require_admin
def update_capa_config():
    data = request.json or {}
    cfg  = load_config()
    if 'enabled'     in data: cfg['capa']['enabled']     = data['enabled']
    if 'binary_path' in data: cfg['capa']['binary_path'] = data['binary_path']
    save_config(cfg)
    return jsonify({'status': 'ok'})


@app.route('/api/capa/test', methods=['POST'])
@require_admin
def test_capa():
    cfg  = load_config()
    capa = cfg.get('capa', {})
    binary = capa.get('binary_path', '/usr/local/bin/capa')
    try:
        result = subprocess.run([binary, '--version'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return jsonify({'status': 'ok', 'version': result.stdout.strip()})
        return jsonify({'status': 'error', 'message': result.stderr.strip()})
    except FileNotFoundError:
        return jsonify({'status': 'error', 'message': f'Binary not found: {binary}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


# ══════════════════════════════════════════════════════════════════
#  ELASTICSEARCH CONFIG (admin only)
# ══════════════════════════════════════════════════════════════════

@app.route('/api/elastic/config', methods=['GET'])
@require_admin
def get_elastic_config():
    cfg = load_config()
    es  = cfg.get('elasticsearch', {})
    # Never send password to frontend
    safe = {k: v for k, v in es.items() if k != 'password'}
    safe['has_password'] = bool(es.get('password'))
    return jsonify(safe)


@app.route('/api/elastic/config', methods=['PUT'])
@require_admin
def update_elastic_config():
    data = request.json or {}
    cfg  = load_config()
    es   = cfg.get('elasticsearch', {})
    for key in ['enabled', 'url', 'username', 'index', 'verify_ssl']:
        if key in data: es[key] = data[key]
    if data.get('password'):
        es['password'] = data['password']
    cfg['elasticsearch'] = es
    save_config(cfg)
    return jsonify({'status': 'ok'})


# ══════════════════════════════════════════════════════════════════
#  SETTINGS (admin only)
# ══════════════════════════════════════════════════════════════════

@app.route('/api/settings', methods=['GET'])
@require_admin
def get_settings():
    cfg = load_config()
    return jsonify(cfg.get('settings', {}))


@app.route('/api/settings', methods=['PUT'])
@require_admin
def update_settings():
    data = request.json or {}
    cfg  = load_config()
    for key in ['app_name', 'mfa_enabled', 'session_timeout']:
        if key in data: cfg['settings'][key] = data[key]
    save_config(cfg)
    return jsonify({'status': 'ok'})


# ══════════════════════════════════════════════════════════════════
#  CTI SCAN ROUTES (require auth)
# ══════════════════════════════════════════════════════════════════

REQUEST_TIMEOUT = 20

def run_builtin_engine(engine_id: str, value: str, typ: str) -> dict:
    """Run a built-in engine by ID."""
    k = get_key(engine_id)

    if engine_id == 'virustotal':
        return _vt(k, value, typ)
    elif engine_id == 'abuseipdb':
        return _abuseipdb(k, value)
    elif engine_id == 'shodan':
        return _shodan(k, value)
    elif engine_id == 'otx':
        return _otx(k, value, typ)
    elif engine_id == 'urlscan':
        return _urlscan(k, value)
    elif engine_id == 'greynoise':
        return _greynoise(k, value)
    elif engine_id == 'malwarebazaar':
        return _malwarebazaar(value)
    elif engine_id == 'threatfox':
        return _threatfox(k, value)
    elif engine_id == 'hybridanalysis':
        return _hybridanalysis(k, value)
    else:
        return {'status': 'error', 'rows': [['Error', f'Unknown engine: {engine_id}']]}


@app.route('/api/scan', methods=['POST'])
@require_auth
def scan():
    """Main scan endpoint — runs all enabled engines for the given value/type."""
    data  = request.json or {}
    value = data.get('value', '').strip()
    typ   = data.get('type', '').strip()

    if not value or not typ:
        return jsonify({'error': 'value and type required'}), 400

    cfg     = load_config()
    engines = [e for e in cfg.get('engines', []) if e.get('enabled')]

    # Filter engines by what they support
    type_map = {
        'md5':    ['hash'], 'sha1': ['hash'], 'sha256': ['hash'],
        'ip':     ['ip'],
        'url':    ['url'],
        'domain': ['domain', 'url'],
    }
    supported_types = type_map.get(typ, [typ])
    engines = [e for e in engines if any(s in e.get('supports', []) for s in supported_types)]

    results = {}
    for engine in engines:
        try:
            results[engine['id']] = run_builtin_engine(engine['id'], value, typ)
        except Exception as ex:
            results[engine['id']] = {'status': 'error', 'rows': [['Error', str(ex)[:80]]]}

    return jsonify(results)


@app.route('/api/virustotal')
@require_auth
def vt_route():
    k, value, typ = get_key('virustotal'), request.args.get('value',''), request.args.get('type','')
    engine = get_engine('virustotal')
    if engine and not engine.get('enabled'): return engine_disabled('VirusTotal')
    if not k: return no_key('VirusTotal')
    try: return jsonify(_vt(k, value, typ))
    except Exception as e: return resp('error', [['Error', str(e)[:80]]])


@app.route('/api/abuseipdb')
@require_auth
def abuseipdb_route():
    k, ip = get_key('abuseipdb'), request.args.get('ip','')
    engine = get_engine('abuseipdb')
    if engine and not engine.get('enabled'): return engine_disabled('AbuseIPDB')
    if not k: return no_key('AbuseIPDB')
    try: return jsonify(_abuseipdb(k, ip))
    except Exception as e: return resp('error', [['Error', str(e)[:80]]])


@app.route('/api/shodan')
@require_auth
def shodan_route():
    k, ip = get_key('shodan'), request.args.get('ip','')
    engine = get_engine('shodan')
    if engine and not engine.get('enabled'): return engine_disabled('Shodan')
    if not k: return no_key('Shodan')
    try: return jsonify(_shodan(k, ip))
    except Exception as e: return resp('error', [['Error', str(e)[:80]]])


@app.route('/api/otx')
@require_auth
def otx_route():
    k, value, typ = get_key('otx'), request.args.get('value',''), request.args.get('type','')
    engine = get_engine('otx')
    if engine and not engine.get('enabled'): return engine_disabled('OTX')
    if not k: return no_key('OTX AlienVault')
    try: return jsonify(_otx(k, value, typ))
    except Exception as e: return resp('error', [['Error', str(e)[:80]]])


@app.route('/api/urlscan')
@require_auth
def urlscan_route():
    k, url = get_key('urlscan'), request.args.get('url','')
    engine = get_engine('urlscan')
    if engine and not engine.get('enabled'): return engine_disabled('URLScan')
    if not k: return no_key('URLScan.io')
    try: return jsonify(_urlscan(k, url))
    except Exception as e: return resp('error', [['Error', str(e)[:80]]])


@app.route('/api/greynoise')
@require_auth
def greynoise_route():
    k, ip = get_key('greynoise'), request.args.get('ip','')
    engine = get_engine('greynoise')
    if engine and not engine.get('enabled'): return engine_disabled('GreyNoise')
    if not k: return no_key('GreyNoise')
    try: return jsonify(_greynoise(k, ip))
    except Exception as e: return resp('error', [['Error', str(e)[:80]]])


@app.route('/api/malwarebazaar')
@require_auth
def malwarebazaar_route():
    engine = get_engine('malwarebazaar')
    if engine and not engine.get('enabled'): return engine_disabled('MalwareBazaar')
    try: return jsonify(_malwarebazaar(request.args.get('hash','')))
    except Exception as e: return resp('error', [['Error', str(e)[:80]]])


@app.route('/api/threatfox')
@require_auth
def threatfox_route():
    k, value = get_key('threatfox'), request.args.get('value','')
    engine = get_engine('threatfox')
    if engine and not engine.get('enabled'): return engine_disabled('ThreatFox')
    try: return jsonify(_threatfox(k, value))
    except Exception as e: return resp('error', [['Error', str(e)[:80]]])


@app.route('/api/hybridanalysis')
@require_auth
def hybridanalysis_route():
    k, hash_ = get_key('hybridanalysis'), request.args.get('hash','')
    engine = get_engine('hybridanalysis')
    if engine and not engine.get('enabled'): return engine_disabled('Hybrid Analysis')
    if not k: return no_key('Hybrid Analysis')
    try: return jsonify(_hybridanalysis(k, hash_))
    except Exception as e: return resp('error', [['Error', str(e)[:80]]])


# ── Individual engine implementations ────────────────────────────

def _vt(k, value, typ):
    if not k: return {'status':'error','rows':[['Config','No VirusTotal API key']],'score':None}
    if typ in ('md5','sha1','sha256'):
        ep, link = f'https://www.virustotal.com/api/v3/files/{value}', f'https://www.virustotal.com/gui/file/{value}'
    elif typ == 'ip':
        ep, link = f'https://www.virustotal.com/api/v3/ip_addresses/{value}', f'https://www.virustotal.com/gui/ip-address/{value}'
    elif typ in ('url','domain'):
        import base64
        uid = base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')
        ep, link = f'https://www.virustotal.com/api/v3/urls/{uid}', f'https://www.virustotal.com/gui/url/{uid}'
    else:
        return {'status':'error','rows':[['Error',f'Unsupported type: {typ}']]}

    r = requests.get(ep, headers={'x-apikey': k}, timeout=REQUEST_TIMEOUT)
    if r.status_code == 404: return {'status':'unknown','rows':[['Result','Not in VT database']],'score':0.0,'link':link}
    if r.status_code == 401: return {'status':'error','rows':[['Error','Invalid VT API key']]}
    r.raise_for_status()

    attrs = r.json().get('data',{}).get('attributes',{})
    stats = attrs.get('last_analysis_stats',{})
    mal, sus = stats.get('malicious',0), stats.get('suspicious',0)
    total = sum(stats.values()) or 1
    score = min(1.0, (mal + sus*0.5) / total)
    status = 'malicious' if mal>0 else 'suspicious' if sus>2 else 'clean'
    rows = [['Malicious',str(mal),'red' if mal else ''],['Suspicious',str(sus),'warn' if sus else ''],['Undetected',str(stats.get('undetected',0))],['Engines',str(total)]]
    if 'meaningful_name' in attrs: rows.insert(0,['Name',attrs['meaningful_name'][:40]])
    if 'reputation' in attrs:
        rep = attrs['reputation']
        rows.append(['Reputation',str(rep),'red' if rep<0 else 'grn'])
    if 'country' in attrs: rows.append(['Country',attrs['country']])
    if attrs.get('tags'): rows.append(['Tags',', '.join(attrs['tags'][:4])])
    return {'status':status,'rows':rows,'score':score,'link':link}


def _abuseipdb(k, ip):
    if not k: return {'status':'error','rows':[['Config','No AbuseIPDB API key']],'score':None}
    r = requests.get('https://api.abuseipdb.com/api/v2/check',headers={'Key':k,'Accept':'application/json'},params={'ipAddress':ip,'maxAgeInDays':90,'verbose':True},timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    d = r.json().get('data',{})
    conf = d.get('abuseConfidenceScore',0)
    score = conf/100.0
    status = 'malicious' if conf>=60 else 'suspicious' if conf>=20 else 'clean'
    rows = [['Abuse score',f'{conf}%','red' if conf>=60 else 'warn' if conf>=20 else 'grn'],['Reports',str(d.get('totalReports',0))],['ISP',(d.get('isp') or 'N/A')[:40]],['Country',d.get('countryCode','N/A')],['Usage',d.get('usageType','N/A')[:35]],['Domain',(d.get('domain') or 'N/A')[:40]],['Whitelisted','Yes' if d.get('isWhitelisted') else 'No']]
    return {'status':status,'rows':rows,'score':score,'link':f'https://www.abuseipdb.com/check/{ip}'}


def _shodan(k, ip):
    if not k: return {'status':'error','rows':[['Config','No Shodan API key']],'score':None}
    r = requests.get(f'https://api.shodan.io/shodan/host/{ip}',params={'key':k},timeout=REQUEST_TIMEOUT)
    if r.status_code == 404: return {'status':'unknown','rows':[['Result','Not indexed by Shodan']],'score':0.0}
    r.raise_for_status()
    d = r.json()
    vulns = list(d.get('vulns',{}).keys())
    score = min(1.0,0.1+0.15*len(vulns)) if vulns else 0.05
    status = 'malicious' if len(vulns)>=3 else 'suspicious' if vulns else 'clean'
    rows = [['Org',(d.get('org') or 'N/A')[:40]],['Country',d.get('country_name','N/A')],['OS',d.get('os','N/A') or 'N/A'],['Open ports',', '.join(str(p) for p in d.get('ports',[])[:8]) or 'None'],['Tags',', '.join(d.get('tags',[])[:5]) or 'None'],['CVEs',str(len(vulns)),'red' if vulns else '']]
    if vulns: rows.append(['CVE list',', '.join(vulns[:4])[:60],'red'])
    return {'status':status,'rows':rows,'score':score,'link':f'https://www.shodan.io/host/{ip}'}


def _otx(k, value, typ):
    if not k: return {'status':'error','rows':[['Config','No OTX API key']],'score':None}
    type_map = {'ip':'IPv4','domain':'domain','url':'url','md5':'file','sha1':'file','sha256':'file'}
    otype = type_map.get(typ,'domain')
    r = requests.get(f'https://otx.alienvault.com/api/v1/indicators/{otype}/{value}/general',headers={'X-OTX-API-KEY':k},timeout=REQUEST_TIMEOUT)
    if r.status_code == 404: return {'status':'unknown','rows':[['Result','No OTX data']],'score':0.0}
    r.raise_for_status()
    d = r.json()
    pulses = d.get('pulse_info',{}).get('count',0)
    score = min(1.0,pulses*0.12)
    status = 'malicious' if pulses>=5 else 'suspicious' if pulses>=1 else 'clean'
    rows = [['Pulses',str(pulses),'red' if pulses>=5 else 'warn' if pulses else ''],['Reputation',str(d.get('reputation',0))],['Type',d.get('type','N/A')]]
    tags = d.get('pulse_info',{}).get('tags',[])
    if tags: rows.append(['Tags',', '.join(tags[:5])[:60]])
    return {'status':status,'rows':rows,'score':score,'link':f'https://otx.alienvault.com/indicator/{otype}/{value}'}


def _urlscan(k, url_val):
    if not k: return {'status':'error','rows':[['Config','No URLScan API key']],'score':None}
    sub = requests.post('https://urlscan.io/api/v1/scan/',headers={'API-Key':k,'Content-Type':'application/json'},json={'url':url_val,'visibility':'private'},timeout=REQUEST_TIMEOUT)
    sub.raise_for_status()
    uuid = sub.json().get('uuid','')
    res = None
    for _ in range(3):
        time.sleep(5)
        res = requests.get(f'https://urlscan.io/api/v1/result/{uuid}/',timeout=REQUEST_TIMEOUT)
        if res.status_code == 200: break
    if not res or res.status_code != 200:
        return {'status':'unknown','rows':[['Status','Scan submitted — results pending'],['UUID',uuid]],'score':0.0,'link':f'https://urlscan.io/result/{uuid}/'}
    d = res.json()
    verdicts = d.get('verdicts',{}).get('overall',{})
    score_v = verdicts.get('score',0)
    mal = verdicts.get('malicious',False)
    score = score_v/100.0
    status = 'malicious' if mal else 'suspicious' if score_v>20 else 'clean'
    rows = [['Malicious','Yes' if mal else 'No','red' if mal else 'grn'],['Score',f'{score_v}/100','red' if score_v>50 else ''],['Categories',', '.join(verdicts.get('categories',[])) or 'None'],['IP',d.get('page',{}).get('ip','N/A')],['Country',d.get('page',{}).get('country','N/A')],['Server',(d.get('page',{}).get('server') or 'N/A')[:30]]]
    return {'status':status,'rows':rows,'score':score,'link':f'https://urlscan.io/result/{uuid}/'}


def _greynoise(k, ip):
    if not k: return {'status':'error','rows':[['Config','No GreyNoise API key']],'score':None}
    r = requests.get(f'https://api.greynoise.io/v3/community/{ip}',headers={'key':k},timeout=REQUEST_TIMEOUT)
    if r.status_code == 404: return {'status':'unknown','rows':[['Result','Not seen by GreyNoise']],'score':0.0}
    r.raise_for_status()
    d = r.json()
    cls = d.get('classification','unknown')
    noise, riot = d.get('noise',False), d.get('riot',False)
    score = 0.8 if cls=='malicious' else 0.35 if (noise and not riot) else 0.05
    status = 'malicious' if cls=='malicious' else 'suspicious' if noise else 'clean'
    rows = [['Classification',cls.title(),'red' if cls=='malicious' else 'grn' if cls=='benign' else ''],['Noise','Yes' if noise else 'No','warn' if noise else ''],['RIOT','Yes' if riot else 'No','grn' if riot else ''],['Name',d.get('name','N/A')]]
    return {'status':status,'rows':rows,'score':score,'link':d.get('link')}


def _malwarebazaar(hash_):
    r = requests.post('https://mb-api.abuse.ch/api/v1/',headers={'User-Agent':'CTI-Hub/2.0'},data={'query':'get_info','hash':hash_},timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    d = r.json()
    if d.get('query_status') == 'hash_not_found':
        return {'status':'unknown','rows':[['Result','Not in MalwareBazaar']],'score':0.0,'link':'https://bazaar.abuse.ch/'}
    info = d.get('data',[{}])[0]
    rows = [['File type',info.get('file_type','N/A')],['File name',(info.get('file_name') or 'N/A')[:40]],['Signature',(info.get('signature') or 'Unknown')[:40],'red'],['First seen',info.get('first_seen','N/A')],['Tags',', '.join(info.get('tags') or ['None'])[:50]]]
    return {'status':'malicious','rows':rows,'score':0.9,'link':f"https://bazaar.abuse.ch/sample/{hash_}/"}


def _threatfox(k, value):
    headers = {'Auth-Key':k} if k else {}
    r = requests.post('https://threatfox-api.abuse.ch/api/v1/',json={'query':'search_ioc','search_term':value},headers=headers,timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    d = r.json()
    if d.get('query_status') == 'no_result':
        return {'status':'clean','rows':[['Result','No IOCs found']],'score':0.0,'link':'https://threatfox.abuse.ch/'}
    iocs = d.get('data',[])
    if isinstance(iocs, str): iocs = []
    score = min(1.0,0.3+0.15*len(iocs))
    top = iocs[0] if iocs and isinstance(iocs[0],dict) else {}
    if not iocs:
        rows = [['Result','No IOCs found']]
    else:
        rows = [['IOCs found',str(len(iocs)),'red'],['Threat type',top.get('threat_type','N/A')[:40]],['Malware',top.get('malware','N/A')[:40],'red'],['Confidence',f"{top.get('confidence_level',0)}%"],['Reporter',top.get('reporter','N/A')]]
        if top.get('tags'): rows.append(['Tags',', '.join(top['tags'][:4])])
    return {'status':'malicious' if iocs else 'clean','rows':rows,'score':score,'link':f"https://threatfox.abuse.ch/ioc/{top.get('id','')}"}


def _hybridanalysis(k, hash_):
    if not k: return {'status':'error','rows':[['Config','No Hybrid Analysis API key']],'score':None}
    r = requests.post('https://www.hybrid-analysis.com/api/v2/search/hash',headers={'api-key':k,'User-Agent':'CTI-Hub/2.0'},data={'hash':hash_},timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    results = r.json()
    if not results: return {'status':'unknown','rows':[['Result','Not found']],'score':0.0}
    top = results[0]
    verdict = top.get('verdict','unknown')
    threat = top.get('threat_score',0) or 0
    score = threat/100.0
    status = 'malicious' if verdict=='malicious' else 'suspicious' if verdict=='suspicious' else 'clean'
    rows = [['Verdict',verdict.title(),'red' if verdict=='malicious' else 'warn' if verdict=='suspicious' else 'grn'],['Threat score',f'{threat}/100','red' if threat>=70 else 'warn' if threat>=30 else ''],['AV detect',f"{top.get('av_detect',0)}%"],['Type',top.get('type_short','N/A')],['Environment',top.get('environment_description','N/A')[:40]]]
    if top.get('vx_family'): rows.append(['Family',top['vx_family'],'red'])
    return {'status':status,'rows':rows,'score':score,'link':f'https://www.hybrid-analysis.com/sample/{hash_}'}


# ══════════════════════════════════════════════════════════════════
#  CAPA (requires auth)
# ══════════════════════════════════════════════════════════════════

ATTACK_SEVERITY = {
    'defense-evasion':'high','privilege-escalation':'high','credential-access':'high',
    'exfiltration':'high','impact':'high','command-and-control':'high',
    'persistence':'med','lateral-movement':'med','collection':'med','discovery':'med',
    'execution':'low','initial-access':'low','reconnaissance':'low',
}


def sha256_of(path):
    h = hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''): h.update(chunk)
    return h.hexdigest()


def parse_capa(raw):
    rules = raw.get('rules',{})
    techniques, seen = [], set()
    malicious, score = False, 0.1
    for rule_name, rule_data in rules.items():
        attacks = rule_data.get('meta',{}).get('attack',[])
        sev = 'low'
        for atk in attacks:
            tactic = atk.get('tactic','').lower().replace(' ','-')
            s = ATTACK_SEVERITY.get(tactic,'low')
            if s=='high': sev='high'; break
            if s=='med' and sev!='high': sev='med'
        if sev=='high': malicious=True; score=max(score,0.75)
        elif sev=='med': score=max(score,0.45)
        for atk in attacks:
            tid, tname = atk.get('id',''), atk.get('technique',rule_name)[:35]
            label = f"{tid}: {tname}" if tid else tname
            if label not in seen:
                seen.add(label); techniques.append({'name':label,'severity':sev})
        for m in rule_data.get('meta',{}).get('mbc',[]):
            mid = m.get('id','')
            label = f"MBC {mid}: {m.get('objective',m.get('behavior',''))[:30]}"
            if mid and label not in seen:
                seen.add(label); techniques.append({'name':label,'severity':sev})
    high = sum(1 for t in techniques if t['severity']=='high')
    med  = sum(1 for t in techniques if t['severity']=='med')
    low  = sum(1 for t in techniques if t['severity']=='low')
    meta = raw.get('meta',{})
    rows = [['Rules matched',str(len(rules)),'red' if len(rules)>10 else 'warn' if len(rules)>3 else ''],['High severity',str(high),'red' if high else ''],['Med severity',str(med),'warn' if med else ''],['Low severity',str(low)],['Arch',meta.get('analysis',{}).get('arch','N/A')],['OS',meta.get('analysis',{}).get('os','N/A')],['Format',meta.get('analysis',{}).get('format','N/A')]]
    status = 'malicious' if malicious else 'suspicious' if score>=0.35 else 'clean'
    return {'status':status,'malicious':malicious,'score':score,'rows':rows,'techniques':techniques[:20]}


def run_capa(filepath, sha256):
    cfg    = load_config()
    capa   = cfg.get('capa',{})
    binary = capa.get('binary_path','/usr/local/bin/capa')
    if not capa.get('enabled'):
        return {'status':'error','rows':[['CAPA','Disabled — enable in Admin → API Management']]}

    cache_file = CACHE_DIR / f'{sha256}.json'
    if cache_file.exists():
        try: return json.loads(cache_file.read_text())
        except Exception: pass

    try:
        result = subprocess.run([binary,'-j',str(filepath)],capture_output=True,text=True,timeout=300)
    except subprocess.TimeoutExpired:
        return {'status':'error','rows':[['Error','CAPA timed out (5 min)']]}
    except FileNotFoundError:
        return {'status':'error','rows':[['Error',f'CAPA not found: {binary}'],['Fix','Set binary path in Admin → API Management']]}

    if result.returncode not in (0,1):
        return {'status':'error','rows':[['CAPA error',(result.stderr or result.stdout or 'Unknown')[:200]]]}

    try: raw = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {'status':'error','rows':[['Error','Could not parse CAPA output']]}

    parsed = parse_capa(raw)
    try: cache_file.write_text(json.dumps(parsed))
    except Exception: pass
    return parsed


@app.route('/api/capa/hash')
@require_auth
def capa_hash():
    cfg = load_config()
    if not cfg.get('capa',{}).get('enabled'):
        return jsonify({'status':'error','rows':[['CAPA','Disabled — enable in Admin → API Management']]})
    sha = request.args.get('hash','').strip().lower()
    if len(sha) != 64:
        return jsonify({'status':'error','rows':[['Error','SHA256 required']]}), 400
    cache_file = CACHE_DIR / f'{sha}.json'
    if cache_file.exists():
        try: return jsonify(json.loads(cache_file.read_text()))
        except Exception: pass
    return jsonify({'status':'unknown','rows':[['CAPA cache','No result for this hash'],['Tip','Upload the file to run CAPA']],'score':None})


@app.route('/api/capa/file', methods=['POST'])
@require_auth
def capa_file():
    cfg = load_config()
    if not cfg.get('capa',{}).get('enabled'):
        return jsonify({'status':'error','rows':[['CAPA','Disabled — enable in Admin → API Management']]})
    if 'file' not in request.files:
        return jsonify({'status':'error','rows':[['Error','No file uploaded']]}), 400
    f      = request.files['file']
    suffix = Path(f.filename or 'sample').suffix
    with tempfile.NamedTemporaryFile(delete=False,suffix=suffix,dir='/tmp') as tmp:
        f.save(tmp.name); tmp_path = Path(tmp.name)
    try:
        sha256 = sha256_of(tmp_path)
        result = run_capa(tmp_path, sha256)
        result['sha256'] = sha256
        return jsonify(result)
    finally:
        try: tmp_path.unlink()
        except Exception: pass


# ══════════════════════════════════════════════════════════════════
#  ELASTICSEARCH SHIPPING (require auth)
# ══════════════════════════════════════════════════════════════════

@app.route('/api/elastic/scan', methods=['POST'])
@require_auth
def elastic_scan():
    import urllib3; urllib3.disable_warnings()
    cfg = load_config()
    es  = cfg.get('elasticsearch',{})
    if not es.get('enabled'):
        return jsonify({'status':'skipped','message':'Elasticsearch shipping disabled'})

    data = request.json or {}
    doc  = {
        '@timestamp':    datetime.datetime.utcnow().isoformat()+'Z',
        'target':        data.get('target',''),
        'target_type':   data.get('type',''),
        'verdict':       data.get('verdict','UNKNOWN'),
        'threat_score':  data.get('score',0),
        'engines_total': data.get('engines_total',0),
        'engines_hit':   data.get('engines_hit',0),
        'results':       data.get('results',{}),
        'techniques':    data.get('techniques',[]),
        'analyst_ip':    request.remote_addr,
        'analyst':       get_current_user().get('sub','unknown'),
    }
    try:
        r = requests.post(
            f"{es['url']}/{es.get('index','cti-scans')}/_doc",
            auth=(es.get('username','elastic'), es.get('password','')),
            json=doc, verify=es.get('verify_ssl',False), timeout=5
        )
        return jsonify({'status':'ok','es_id':r.json().get('_id')})
    except Exception as ex:
        return jsonify({'status':'error','detail':str(ex)})


# ══════════════════════════════════════════════════════════════════
#  HEALTH
# ══════════════════════════════════════════════════════════════════

@app.route('/health')
def health():
    cfg      = load_config()
    users    = load_users()
    capa_cfg = cfg.get('capa',{})
    capa_ok  = False
    if capa_cfg.get('enabled'):
        try:
            capa_ok = subprocess.run([capa_cfg.get('binary_path','capa'),'--version'],capture_output=True,timeout=5).returncode == 0
        except Exception:
            pass
    return jsonify({
        'status':      'ok',
        'version':     '2.0.0',
        'setup_done':  len(users) > 0,
        'engines':     sum(1 for e in cfg.get('engines',[]) if e.get('enabled')),
        'capa':        'available' if capa_ok else ('disabled' if not capa_cfg.get('enabled') else 'not found'),
        'elastic':     'enabled' if cfg.get('elasticsearch',{}).get('enabled') else 'disabled',
    })


# ══════════════════════════════════════════════════════════════════
#  STATIC FILES
# ══════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/login')
def login_page():
    return send_from_directory('static', 'login.html')

@app.route('/admin')
def admin_page():
    return send_from_directory('static', 'admin.html')

@app.route('/setup')
def setup_page():
    return send_from_directory('static', 'setup.html')


if __name__ == '__main__':
    print("=" * 55)
    print("  CTI Hub v2.0 — Starting")
    print("=" * 55)
    users = load_users()
    if not users:
        print("  ⚠  No users found — visit http://localhost:5000/setup")
    else:
        print(f"  Users: {len(users)}")
    cfg = load_config()
    print(f"  Engines: {sum(1 for e in cfg.get('engines',[]) if e.get('enabled'))} enabled")
    print(f"  Config:  {CONFIG_FILE}")
    print(f"  Listening: http://0.0.0.0:5000")
    print("=" * 55)
    app.run(host='0.0.0.0', port=5000, debug=False)
