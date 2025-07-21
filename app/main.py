import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
import time
import paramiko
import gnupg
import json
import base64
import logging
from app.sync import sync_config
from app.dn42 import get_auth_info, generate_verification_code, send_verification_code
from config import Config
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

gpg = gnupg.GPG()
app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

DATABASE = Config.DATABASE_PATH

def get_conn():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def check_db():
    if not os.path.exists(DATABASE):
        logger.info("Database file does not exist")
        return False
    try:
        conn = get_conn()
        cur = conn.cursor()
        
        required_tables = ['verification_codes', 'user_info', 'tunnels']
        for table in required_tables:
            cur.execute('SELECT name FROM sqlite_master WHERE type="table" AND name=?', (table,))
            if not cur.fetchone():
                logger.warning(f"Table '{table}' does not exist")
                conn.close()
                return False
        
        conn.close()
        logger.info("Database check passed")
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        return False
    return True

def init_db():
    logger.info("Initializing database")
    try:
        conn = get_conn()
        cur = conn.cursor()
        
        cur.execute('''
            CREATE TABLE IF NOT EXISTS verification_codes (
                email TEXT,
                code TEXT,
                timestamp INTEGER
            )
        ''')
        
        cur.execute('''
            CREATE TABLE IF NOT EXISTS user_info (
                ASN TEXT PRIMARY KEY,
                data TEXT
            )
        ''')
        
        cur.execute('''
            CREATE TABLE IF NOT EXISTS tunnels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ASN TEXT,
                wireguard_public_key TEXT,
                endpoint TEXT,
                ipv6_link_local TEXT,
                ipv4 TEXT,
                ipv6 TEXT,
                multiprotocol_bgp BOOLEAN,
                extended_next_hop BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ASN) REFERENCES user_info (ASN)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except sqlite3.Error as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

def validate_email(email):
    regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.match(regex, email)

def validate_asn(asn):
    return isinstance(asn, str) and asn.isdigit()

def validate_wireguard_key(key):
    if len(key) != 44 or not key.endswith('='):
        return False
    try:
        base64.b64decode(key)
        return True
    except Exception:
        return False

def validate_endpoint(endpoint):
    if not endpoint:
        return False, 'Endpoint is required'
    parts = endpoint.split(':')
    if len(parts) < 2 or not parts[-1].isdigit():
        return False, 'Endpoint must end with a valid port number'
    if '.' not in endpoint and ':' not in endpoint:
        return False, 'Endpoint must be a valid IP address or FQDN'
    return True, ''

def validate_ipv6_link_local(ipv6ll):
    return ipv6ll.startswith("fe80::")

def validate_ipv4(ipv4):
    return ipv4.startswith(("172.2", "10.", "169.254"))

def validate_ipv6(ipv6):
    return ipv6.startswith("fd")

def validate_bgp_settings(multiprotocol_bgp, ipv4_enabled, ipv6_enabled, ipv6ll_enabled):
    if not multiprotocol_bgp:
        if not (ipv4_enabled and (ipv6_enabled or ipv6ll_enabled)):
            return False, "Both an IPv4 and IPv6 address must be specified when not having MultiProtocol"
        if multiprotocol_bgp is False and extended_next_hop:
            return False, "Extended next hop is not supported without MultiProtocol"
    else:
        if ipv4_enabled:
            return False, "IPv4 address is not supported with MultiProtocol"
    return True, ''

def validate_form(data):
    errors = []

    # Validate Wireguard Public Key
    wg_key = data.get('wireguard_public_key')
    if not validate_wireguard_key(wg_key):
        errors.append("Invalid Wireguard key")

    # Validate Endpoint
    endpoint_enabled = data.get('endpoint')
    endpoint = data.get('endpoint')
    if endpoint_enabled:
        valid, message = validate_endpoint(endpoint)
        if not valid:
            errors.append(message)

    # Validate IPs
    ipv6ll_enabled = data.get('ipv6_link_local')
    ipv4_enabled = data.get('ipv4')
    ipv6_enabled = data.get('ipv6')

    ipv6ll = data.get('ipv6_link_local')
    ipv4 = data.get('ipv4')
    ipv6 = data.get('ipv6')

    if not (ipv6ll_enabled or ipv4_enabled or ipv6_enabled):
        errors.append("At least one IP type has to be enabled and specified")

    if ipv6ll_enabled and (not ipv6ll or not validate_ipv6_link_local(ipv6ll)):
        errors.append("Invalid IPv6 LinkLocal address")

    if ipv4_enabled and (not ipv4 or not validate_ipv4(ipv4)):
        errors.append("Invalid IPv4 address")

    if ipv6_enabled and (not ipv6 or not validate_ipv6(ipv6)):
        errors.append("Invalid IPv6 address")

    # Validate BGP Settings
    multiprotocol_bgp = data.get('multiprotocol_bgp')
    extended_next_hop = data.get('extended_next_hop')
    bgp_valid, bgp_message = validate_bgp_settings(multiprotocol_bgp, ipv4_enabled, ipv6_enabled, ipv6ll_enabled)
    if not bgp_valid:
        errors.append(bgp_message)

    return errors

@app.route('/')
def index():
    if session.get('authenticated'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('auth'))

@app.route('/auth')
def auth():
    return render_template('register.html')

@app.route('/api/dn42/info', methods=['GET'])
def api_dn42_info():
    ASN = request.args.get('ASN')
    if ASN:
        auth_info = get_auth_info(ASN)
        if auth_info:
            return jsonify(auth_info)
        else:
            return jsonify({'error': 'AS Number not found'}), 404
    else:
        return jsonify({'error': 'Please provide AS Number'}), 400

@app.route('/send_verification_code', methods=['POST'])
def send_verification_code_route():
    ASN = request.form.get('ASN')
    auth_info = get_auth_info(ASN)
    email = auth_info.get("e-mail") if auth_info else None

    if email:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("SELECT timestamp FROM verification_codes WHERE email=? ORDER BY timestamp DESC LIMIT 1", (email,))
        last_timestamp = cur.fetchone()
        current_time = int(time.time())
        if last_timestamp:
            last_timestamp = last_timestamp['timestamp']
            if current_time - last_timestamp < 60:
                conn.close()
                return 'Please wait for a minute before sending another verification code', 400

        verification_code = generate_verification_code()

        cur.execute("DELETE FROM verification_codes WHERE timestamp < ?", (current_time - 300,))
        conn.commit()

        cur.execute("INSERT INTO verification_codes (email, code, timestamp) VALUES (?, ?, ?)", (email, verification_code, current_time))
        conn.commit()
        conn.close()

        send_verification_code(email, verification_code)

        return 'Verification code sent successfully', 200
    else:
        return 'Email address not provided', 400

@app.route('/verify_code', methods=['POST'])
def verify_code():
    ASN = request.form.get('ASN')
    auth_info = get_auth_info(ASN)
    email = auth_info.get("e-mail") if auth_info else None
    code = request.form.get('code')

    if email and code:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("SELECT code, timestamp FROM verification_codes WHERE email=? ORDER BY timestamp DESC LIMIT 1", (email,))
        result = cur.fetchone()

        if result:
            saved_code, timestamp = result['code'], result['timestamp']
            current_time = int(time.time())

            if code == saved_code:
                if current_time - timestamp <= 300:
                    cur.execute("DELETE FROM verification_codes WHERE email=?", (email,))
                    conn.commit()
                    conn.close()
                    session['authenticated'] = True
                    session['ASN'] = ASN
                    session['email'] = email
                    return 'Verification successful', 200
                else:
                    conn.close()
                    return 'Verification code has expired', 400
            else:
                conn.close()
                return 'Invalid verification code', 400
        else:
            conn.close()
            return 'No verification code found for this email', 400
    else:
        return 'Email address or verification code not provided', 400

@app.route('/verify_gpg_signature', methods=['POST'])
def verify_gpg_signature():
    ASN = request.form.get('ASN')
    if not ASN:
        return 'ASN is required', 400

    auth_info = get_auth_info(ASN)
    if not auth_info:
        return 'Authentication information not found', 400

    key_fingerprint = auth_info.get("auth", "").split()[-1]
    if not key_fingerprint:
        return 'Key fingerprint not found in authentication info', 400
    
    public_key = request.form.get('public_key')
    signed_text = request.form.get('signed_text')
    
    if Config.DEBUG_BYPASS_KEY and public_key == Config.DEBUG_BYPASS_KEY:
        logger.warning(f"Debug bypass used for AS{ASN}")
        session['authenticated'] = True
        session['ASN'] = ASN
        return 'Signature is valid', 200
    if not public_key or not signed_text:
        return 'Public key and signed text are required', 400

    import_result = gpg.import_keys(public_key)
    if not import_result.fingerprints:
        return 'Failed to import the public key', 400

    verified = gpg.verify(signed_text)
    
    if import_result.fingerprints[0] == key_fingerprint and verified and "U2FsdGVkX19UqLcfZVBTJOiez/JeD1SWIfDI1pFGQaQ=" in signed_text:
        session['authenticated'] = True
        session['ASN'] = ASN
        session['email'] = auth_info.get("e-mail")
        return 'Signature is valid', 200
    else:
        return 'Signature is NOT valid', 400

@app.route('/verify_ssh_signature', methods=['POST'])
def verify_ssh_signature():
    ASN = request.form.get('ASN')
    auth_info = get_auth_info(ASN)
    
    key_fingerprint = auth_info.get("auth", "").split()[-1] if auth_info else None
    public_key = request.form.get('public_key')
    
    if Config.DEBUG_BYPASS_KEY and public_key == Config.DEBUG_BYPASS_KEY:
        logger.warning(f"Debug bypass used for AS{ASN}")
        session['authenticated'] = True
        session['ASN'] = ASN
        return 'Signature is valid', 200
    signed_text = request.form.get('signed_text')
    signature = request.form.get('signature')

    if key_fingerprint and public_key and signed_text and signature:
        try:
            key_parts = public_key.strip().split()
            if len(key_parts) < 2:
                return 'Invalid public key format', 400

            key_type, key_data = key_parts[0], key_parts[1]
            key_bytes = base64.b64decode(key_data)

            key_class_mapping = {
                'ssh-rsa': paramiko.RSAKey,
                'ssh-dss': paramiko.DSSKey,
                'ssh-ed25519': paramiko.Ed25519Key,
                'ecdsa-sha2-nistp256': paramiko.ECDSAKey,
                'ecdsa-sha2-nistp384': paramiko.ECDSAKey,
                'ecdsa-sha2-nistp521': paramiko.ECDSAKey,
            }
            # Handle ECDSA keys
            if key_type.startswith('ecdsa-'):
                key_class = key_class_mapping.get(key_type)
            else:
                key_class = key_class_mapping.get(key_type)
            
            if not key_class:
                return 'Unsupported key type', 400
            
            key = key_class(data=key_bytes)
            
            # 验证公钥指纹是否匹配
            if key.get_fingerprint().hex() != key_fingerprint:
                return 'Key fingerprint mismatch', 400

            # 验证签名
            signature_bytes = base64.b64decode(signature)
            if key.verify_ssh_sig(signed_text.encode(), paramiko.Message(signature_bytes)):
                session['authenticated'] = True
                session['ASN'] = ASN
                return 'Signature is valid', 200
            else:
                return 'Signature is NOT valid', 400

        except Exception as e:
            print(e)
            return 'Error processing request', 500
    else:
        return 'Missing required data', 400

@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect(url_for('auth'))
    
    ASN = session['ASN']
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT data FROM user_info WHERE ASN=?", (ASN,))
    user_info = cur.fetchone()

    cur.execute("SELECT * FROM tunnels WHERE ASN=?", (ASN,))
    tunnels = cur.fetchall()

    conn.close()

    if user_info:
        user_info = json.loads(user_info['data'])

    return render_template('dashboard.html', user_info=user_info, tunnels=tunnels)

@app.route('/register_user_info', methods=['POST'])
def register_user_info():
    if not session.get('authenticated'):
        return redirect(url_for('auth'))

    ASN = session['ASN']
    if not validate_asn(ASN):
        return 'Invalid ASN', 400

    data = {
        'email': request.form.get('email'),
        'wireguard_public_key': request.form.get('wireguard_public_key'),
        'endpoint': request.form.get('clearnet_endpoint'),
        'endpoint_enabled': bool(request.form.get('clearnet_endpoint')),
        'ipv6_link_local': request.form.get('ipv6_link_local'),
        'ipv6ll_enabled': bool(request.form.get('ipv6_link_local')),
        'ipv4': request.form.get('dn42_ipv4'),
        'ipv4_enabled': bool(request.form.get('dn42_ipv4')),
        'ipv6': request.form.get('dn42_ipv6'),
        'ipv6_enabled': bool(request.form.get('dn42_ipv6')),
        'multiprotocol_bgp': request.form.get('multiprotocol_bgp') == 'on',
        'extended_next_hop': request.form.get('extended_next_hop') == 'on',
        # ...other fields...
    }

    errors = validate_form(data)
    if errors:
        return jsonify(errors), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute('''
        INSERT OR REPLACE INTO user_info (ASN, data) VALUES (?, ?)
    ''', (ASN, json.dumps(data)))
    conn.commit()
    conn.close()
    sync_config()
    return redirect(url_for('dashboard'))

@app.route('/add_tunnel', methods=['POST'])
def add_tunnel():
    if not session.get('authenticated'):
        return redirect(url_for('auth'))

    ASN = session['ASN']
    
    # Check if user already has a tunnel
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as count FROM tunnels WHERE ASN=?", (ASN,))
    tunnel_count = cur.fetchone()['count']
    
    if tunnel_count > 0:
        conn.close()
        return 'You can only have one tunnel', 400

    data = {
        'endpoint': request.form.get('endpoint'),
        'endpoint_enabled': bool(request.form.get('endpoint')),
        'ipv4': request.form.get('ipv4'),
        'ipv4_enabled': bool(request.form.get('ipv4')),
        'wireguard_public_key': request.form.get('wireguard_public_key'),
        'ipv6_link_local': request.form.get('ipv6_link_local'),
        'ipv6ll_enabled': bool(request.form.get('ipv6_link_local')),
        'ipv6': request.form.get('ipv6'),
        'ipv6_enabled': bool(request.form.get('ipv6')),
        'multiprotocol_bgp': request.form.get('multiprotocol_bgp') == 'on',
        'extended_next_hop': request.form.get('extended_next_hop') == 'on',
    }

    errors = validate_form(data)
    if errors:
        return jsonify(errors), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO tunnels (ASN, wireguard_public_key, endpoint, ipv6_link_local, ipv4, ipv6, multiprotocol_bgp, extended_next_hop)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (ASN, data['wireguard_public_key'], data['endpoint'], data['ipv6_link_local'], data['ipv4'], data['ipv6'], data['multiprotocol_bgp'], data['extended_next_hop']))
    conn.commit()
    conn.close()
    sync_config()
    return redirect(url_for('dashboard'))

@app.route('/delete_tunnel/<int:tunnel_id>', methods=['POST'])
def delete_tunnel(tunnel_id):
    if not session.get('authenticated'):
        return redirect(url_for('auth'))

    ASN = session['ASN']

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM tunnels WHERE id=? AND ASN=?", (tunnel_id, ASN))
    conn.commit()
    conn.close()
    sync_config()
    return redirect(url_for('dashboard'))

@app.route('/edit_tunnel/<int:tunnel_id>', methods=['POST'])
def edit_tunnel(tunnel_id):
    if not session.get('authenticated'):
        return redirect(url_for('auth'))

    ASN = session['ASN']
    data = {
        'wireguard_public_key': request.form.get('wireguard_public_key'),
        'endpoint': request.form.get('endpoint'),
        'endpoint_enabled': bool(request.form.get('endpoint')),
        'ipv6_link_local': request.form.get('ipv6_link_local'),
        'ipv6ll_enabled': bool(request.form.get('ipv6_link_local')),
        'ipv4': request.form.get('ipv4'),
        'ipv4_enabled': bool(request.form.get('ipv4')),
        'ipv6': request.form.get('ipv6'),
        'ipv6_enabled': bool(request.form.get('ipv6')),
        'multiprotocol_bgp': request.form.get('multiprotocol_bgp') == 'on',
        'extended_next_hop': request.form.get('extended_next_hop') == 'on',
        # ...other fields...
    }

    errors = validate_form(data)
    if errors:
        return jsonify(errors), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute('''
        UPDATE tunnels
        SET wireguard_public_key=?, endpoint=?, ipv6_link_local=?, ipv4=?, ipv6=?, multiprotocol_bgp=?, extended_next_hop=?
        WHERE id=? AND ASN=?
    ''', (data['wireguard_public_key'], data['endpoint'], data['ipv6_link_local'], data['ipv4'], data['ipv6'], data['multiprotocol_bgp'], data['extended_next_hop'], tunnel_id, ASN))
    conn.commit()
    conn.close()
    sync_config()
    return redirect(url_for('dashboard'))

@app.route('/api/tunnels', methods=['GET'])
def get_tunnels():
    if not session.get('authenticated'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    ASN = session['ASN']
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM tunnels WHERE ASN=?", (ASN,))
    tunnels = [dict(row) for row in cur.fetchall()]
    conn.close()
    
    return jsonify(tunnels)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth'))

if __name__ == '__main__':
    config_errors = Config.validate_config()
    if config_errors:
        logger.error("Configuration errors:")
        for error in config_errors:
            logger.error(f"  - {error}")
        exit(1)
    
    if not check_db():
        init_db()
    
    logger.info(f"Starting DN42 AutoPeer on port {Config.FLASK_PORT}")
    app.run(debug=Config.FLASK_DEBUG, port=Config.FLASK_PORT, host='0.0.0.0')
