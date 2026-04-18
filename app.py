from flask import Flask, render_template, redirect, request, jsonify, g, make_response
import psycopg2, psycopg2.extras, psycopg2.errors
import os, hashlib, hmac, json, jwt, datetime, functools, secrets, re, bcrypt, smtplib, base64
from email.message import EmailMessage
from urllib.parse import urlencode
import requests as _requests

# Load .env file when running locally (no-op if the file doesn't exist or if
# the variables are already set by the host environment, e.g. Replit Secrets).
try:
    from dotenv import load_dotenv
    load_dotenv(override=False)
except ImportError:
    pass

app = Flask(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get('JWT_SECRET', 'gh-zero-trust-secret-2024-change-in-prod')
_raw_db_url = (os.environ.get('SUPABASE_DB_URL') or '').strip()
# Auto-correct common typo: /postgre → /postgres
DATABASE_URL = _raw_db_url + 's' if _raw_db_url.endswith('/postgre') else _raw_db_url
ACCESS_TOKEN_HOURS = float(os.environ.get('ACCESS_TOKEN_HOURS', '1'))
AUTH_COOKIE_NAME = 'gh_access_token'
MFA_OTP_TTL_MINUTES = int(os.environ.get('MFA_OTP_TTL_MINUTES', '10'))
MFA_OTP_MAX_ATTEMPTS = int(os.environ.get('MFA_OTP_MAX_ATTEMPTS', '5'))
MFA_OTP_RESEND_SECONDS = int(os.environ.get('MFA_OTP_RESEND_SECONDS', '60'))

if not DATABASE_URL:
    raise RuntimeError(
        "SUPABASE_DB_URL is not set.\n"
        "  • Locally: create a .env file with SUPABASE_DB_URL=<your connection string>\n"
        "  • On Replit: add it under Secrets in the sidebar"
    )

GOOGLE_CLIENT_ID     = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')

@app.after_request
def add_no_cache(response):
    if os.environ.get('NODE_ENV') != 'production':
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

# ── Database ──────────────────────────────────────────────────────────────────
# One connection per request, stored on Flask's g object.
# psycopg2 operates in transaction mode by default (autocommit=False).
# Every write path must call db.commit() on success and db.rollback() on any
# exception — failure to rollback leaves the connection in an aborted state,
# causing all subsequent queries in the same request to fail.

def get_db():
    """Return the per-request psycopg2 connection, opening it on first access."""
    if 'db' not in g:
        g.db = psycopg2.connect(DATABASE_URL)
    return g.db

def _cur(db):
    """Return a RealDictCursor for the given connection."""
    return db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

@app.teardown_appcontext
def close_db(e=None):
    """Close the per-request connection on teardown. Never reuse across requests."""
    db = g.pop('db', None)
    if db:
        try:
            db.rollback()   # discard any uncommitted state before closing
        except Exception:
            pass
        db.close()

# ── Password Hashing ──────────────────────────────────────────────────────────

_SHA256_RE = re.compile(r'^[0-9a-f]{64}$')

def _ensure_str(value):
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode('utf-8')
    raise TypeError(f'Expected str or bytes, got {type(value).__name__}')

def _is_sha256_hash(h):
    return bool(_SHA256_RE.match(_ensure_str(h)))

def _hash_pw(password):
    salt = bcrypt.gensalt()
    return _ensure_str(bcrypt.hashpw(_ensure_str(password).encode('utf-8'), salt))

def _verify_pw(stored_hash, password):
    stored_hash = _ensure_str(stored_hash)
    password    = _ensure_str(password)
    if _is_sha256_hash(stored_hash):
        return stored_hash == hashlib.sha256(password.encode('utf-8')).hexdigest()
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

def _hash_mfa_temp_token(temp_token):
    return hmac.new(
        SECRET_KEY.encode('utf-8'),
        temp_token.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

def _hash_otp(user_id, temp_token, code):
    return hmac.new(
        SECRET_KEY.encode('utf-8'),
        f'{user_id}:{temp_token}:{code}'.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

def _smtp_settings():
    settings = {
        'host': os.environ.get('SMTP_HOST', '').strip(),
        'port': int(os.environ.get('SMTP_PORT', '587')),
        'username': os.environ.get('SMTP_USERNAME', '').strip(),
        'password': os.environ.get('SMTP_PASSWORD', '').strip(),
        'from_email': os.environ.get('SMTP_FROM_EMAIL', '').strip(),
        'from_name': os.environ.get('SMTP_FROM_NAME', 'GuardianHealth').strip() or 'GuardianHealth',
    }
    missing = [k for k, v in settings.items() if k != 'port' and not v]
    if missing:
        raise RuntimeError('Missing SMTP configuration: ' + ', '.join(missing))
    return settings

def _send_otp_email(user, code):
    settings = _smtp_settings()
    msg = EmailMessage()
    msg['Subject'] = 'Your GuardianHealth verification code'
    msg['From'] = f'{settings["from_name"]} <{settings["from_email"]}>'
    msg['To'] = user['email']
    msg.set_content(
        f'Hello {user["name"]},\n\n'
        f'Your GuardianHealth verification code is: {code}\n\n'
        f'This code expires in {MFA_OTP_TTL_MINUTES} minutes. '
        'If you did not try to sign in, contact your administrator immediately.\n\n'
        'GuardianHealth Security'
    )
    with smtplib.SMTP(settings['host'], settings['port'], timeout=15) as smtp:
        smtp.starttls()
        smtp.login(settings['username'], settings['password'])
        smtp.send_message(msg)

def _mask_email(email):
    local, _, domain = email.partition('@')
    if len(local) <= 2:
        masked_local = local[:1] + '*'
    else:
        masked_local = local[:1] + '*' * (len(local) - 2) + local[-1:]
    return masked_local + '@' + domain

def _issue_email_otp(db, user, temp_token):
    code = f'{secrets.randbelow(1000000):06d}'
    otp_id = 'otp_' + secrets.token_hex(10)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=MFA_OTP_TTL_MINUTES)
    code_hash = _hash_otp(user['id'], temp_token, code)
    temp_token_hash = _hash_mfa_temp_token(temp_token)
    with _cur(db) as cur:
        cur.execute("UPDATE mfa_email_otps SET used=TRUE WHERE user_id=%s AND used=FALSE", (user['id'],))
        cur.execute(
            'INSERT INTO mfa_email_otps(id,user_id,temp_token_hash,code_hash,expires_at,attempts,used) '
            'VALUES(%s,%s,%s,%s,%s,0,FALSE)',
            (otp_id, user['id'], temp_token_hash, code_hash, expires_at)
        )
    db.commit()
    try:
        _send_otp_email(user, code)
    except Exception:
        with _cur(db) as cur:
            cur.execute('UPDATE mfa_email_otps SET used=TRUE WHERE id=%s', (otp_id,))
        db.commit()
        raise
    return expires_at

# ── Audit Chain Hashing ───────────────────────────────────────────────────────

def _make_hash(data, prev_hash=''):
    payload = prev_hash + json.dumps(data, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()

# ── Database Initialisation ───────────────────────────────────────────────────

def init_db():
    """
    Create tables + indexes on startup.
    Uses a dedicated connection separate from Flask's per-request g.db.
    """
    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            # ── Tables ────────────────────────────────────────────────────────
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id            TEXT PRIMARY KEY,
                    name          TEXT NOT NULL,
                    email         TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role          TEXT NOT NULL DEFAULT 'patient',
                    status        TEXT NOT NULL DEFAULT 'active',
                    mfa_enabled   SMALLINT NOT NULL DEFAULT 1,
                    mfa_secret    TEXT,
                    last_login    TEXT,
                    department    TEXT,
                    created_at    TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS patients (
                    id           TEXT PRIMARY KEY,
                    name         TEXT NOT NULL,
                    age          INTEGER,
                    condition    TEXT,
                    last_visit   TEXT,
                    status       TEXT DEFAULT 'Stable',
                    doctor_id    TEXT,
                    consent_flag BOOLEAN DEFAULT FALSE
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id         TEXT PRIMARY KEY,
                    hash       TEXT NOT NULL,
                    prev_hash  TEXT DEFAULT '',
                    action     TEXT NOT NULL,
                    user_email TEXT NOT NULL,
                    user_id    TEXT,
                    ip         TEXT DEFAULT '',
                    status     TEXT DEFAULT 'Verified',
                    timestamp  TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id         TEXT PRIMARY KEY,
                    user_id    TEXT NOT NULL,
                    device     TEXT,
                    ip         TEXT,
                    location   TEXT,
                    status     TEXT DEFAULT 'Active',
                    token_jti  TEXT,
                    csrf_token TEXT,
                    expires_at TIMESTAMPTZ,
                    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
                    terminated_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cur.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS token_jti TEXT")
            cur.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS csrf_token TEXT")
            cur.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ")
            cur.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ DEFAULT NOW()")
            cur.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS terminated_at TIMESTAMPTZ")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS mfa_email_otps (
                    id         TEXT PRIMARY KEY,
                    user_id    TEXT NOT NULL,
                    temp_token_hash TEXT,
                    code_hash  TEXT NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    attempts   INTEGER NOT NULL DEFAULT 0,
                    used       BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cur.execute("ALTER TABLE mfa_email_otps ADD COLUMN IF NOT EXISTS temp_token_hash TEXT")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id TEXT")
            cur.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS block_index INTEGER")
            cur.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS block_hash TEXT")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS blockchain (
                    block_index     INTEGER PRIMARY KEY,
                    timestamp       TEXT NOT NULL,
                    data            JSONB NOT NULL,
                    previous_hash   TEXT NOT NULL,
                    nonce           INTEGER NOT NULL DEFAULT 0,
                    difficulty_used INTEGER NOT NULL DEFAULT 3,
                    hash            TEXT NOT NULL,
                    signature       TEXT
                )
            """)
            cur.execute("""
                CREATE OR REPLACE RULE no_update_blockchain AS
                    ON UPDATE TO blockchain DO INSTEAD NOTHING
            """)
            cur.execute("""
                CREATE OR REPLACE RULE no_delete_blockchain AS
                    ON DELETE TO blockchain DO INSTEAD NOTHING
            """)

            # ── Indexes ───────────────────────────────────────────────────────
            # users.email is already covered by the UNIQUE constraint.
            # audit_logs.timestamp: used in ORDER BY on every read/write.
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp
                ON audit_logs(timestamp)
            """)
            # sessions.user_id: used when filtering sessions by user.
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_user_id
                ON sessions(user_id)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_status
                ON sessions(status)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
                ON sessions(expires_at)
            """)
            # audit_logs.user_email: used when non-admin users query their own logs.
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_logs_user_email
                ON audit_logs(user_email)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_mfa_email_otps_user_id
                ON mfa_email_otps(user_id, created_at DESC)
            """)

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

# ── Auth Helpers ───────────────────────────────────────────────────────────────

def create_token(user_id, role=None, email=None, expiry_hours=None, token_type='access', session_id=None, jti=None, expires_at=None):
    if expiry_hours is None:
        expiry_hours = ACCESS_TOKEN_HOURS if token_type == 'access' else 24
    if expires_at is None:
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=expiry_hours)
    payload = {
        'sub': user_id,
        'type': token_type,
        'exp': expires_at,
        'iat': datetime.datetime.utcnow(),
    }
    if token_type != 'access' and role:
        payload['role'] = role
    if token_type != 'access' and email:
        payload['email'] = email
    if session_id:
        payload['sid'] = session_id
    if jti:
        payload['jti'] = jti
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def _create_session(db, user, ip):
    session_id = 'sess_' + secrets.token_hex(8)
    token_jti = 'jti_' + secrets.token_hex(12)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=ACCESS_TOKEN_HOURS)
    with _cur(db) as cur:
        cur.execute(
            'INSERT INTO sessions(id,user_id,device,ip,location,status,token_jti,csrf_token,expires_at,last_seen_at) '
            'VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())',
            (session_id, user['id'], _parse_device(request.headers.get('User-Agent', '')), ip, 'Unknown', 'Active', token_jti, csrf_token, expires_at)
        )
    return session_id, token_jti, csrf_token, expires_at

def _session_cookie_response(payload, token=None, clear=False, status=200):
    resp = make_response(jsonify(payload), status)
    if clear:
        resp.delete_cookie(AUTH_COOKIE_NAME, path='/', samesite='Lax', secure=request.is_secure, httponly=True)
    if token:
        resp.set_cookie(
            AUTH_COOKIE_NAME,
            token,
            max_age=int(ACCESS_TOKEN_HOURS * 3600),
            path='/',
            samesite='Lax',
            secure=request.is_secure,
            httponly=True,
        )
    return resp

def _terminate_user_sessions(db, user_id, except_session_id=None):
    params = [user_id]
    sql = "UPDATE sessions SET status='Terminated', terminated_at=NOW() WHERE user_id=%s AND status='Active'"
    if except_session_id:
        sql += ' AND id<>%s'
        params.append(except_session_id)
    with _cur(db) as cur:
        cur.execute(sql, params)

def require_auth(roles=None):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get('Authorization', '')
            token_source = 'header' if auth.startswith('Bearer ') else 'cookie'
            if auth.startswith('Bearer '):
                token = auth[7:]
            else:
                token = request.cookies.get(AUTH_COOKIE_NAME, '')
            if not token:
                return jsonify({'error': 'No token'}), 401
            try:
                data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            if data.get('type', 'access') != 'access':
                return jsonify({'error': 'Invalid token'}), 401
            session_id = data.get('sid')
            if not session_id:
                return jsonify({'error': 'Invalid session'}), 401
            db = get_db()
            with _cur(db) as cur:
                cur.execute(
                    'SELECT s.*, (s.expires_at IS NOT NULL AND s.expires_at <= NOW()) AS session_expired, '
                    'u.email AS user_email, u.role AS user_role, u.status AS user_status, u.name AS user_name '
                    'FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=%s',
                    (session_id,)
                )
                session = cur.fetchone()
            if not session or session['user_id'] != data.get('sub'):
                return jsonify({'error': 'Invalid session'}), 401
            if session['status'] != 'Active':
                return jsonify({'error': 'Session revoked'}), 401
            if session['session_expired']:
                try:
                    with _cur(db) as cur:
                        cur.execute("UPDATE sessions SET status='Expired' WHERE id=%s AND status='Active'", (session_id,))
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
                return jsonify({'error': 'Session expired'}), 401
            if session['user_status'] != 'active':
                return jsonify({'error': 'Account inactive'}), 403
            if token_source == 'cookie' and request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
                csrf = request.headers.get('X-CSRF-Token', '')
                if not csrf or not session.get('csrf_token') or not hmac.compare_digest(csrf, session['csrf_token']):
                    return jsonify({'error': 'Invalid CSRF token'}), 403
            current_role = session['user_role']
            if roles and current_role not in roles:
                return jsonify({'error': 'Forbidden'}), 403
            data['role'] = current_role
            data['email'] = session['user_email']
            g.token_data = data
            g.session = session
            try:
                with _cur(db) as cur:
                    cur.execute('UPDATE sessions SET last_seen_at=NOW() WHERE id=%s', (session_id,))
                db.commit()
            except Exception:
                db.rollback()
                raise
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ── Audit Logging ─────────────────────────────────────────────────────────────

def _write_audit(action, user_email, ip='', status='Verified', user_id=None):
    """
    Append a tamper-evident audit log entry to PostgreSQL and the blockchain.
    Rolls back and re-raises on any DB error so the caller's transaction
    is not left in an aborted state.
    """
    db = get_db()
    try:
        with _cur(db) as cur:
            cur.execute('SELECT hash FROM audit_logs ORDER BY timestamp DESC LIMIT 1')
            last = cur.fetchone()
            prev   = last['hash'] if last else ''
            log_id = 'log_' + secrets.token_hex(8)
            ts     = datetime.datetime.utcnow().isoformat(sep=' ', timespec='seconds')
            h      = _make_hash({'id': log_id, 'action': action, 'user': user_email, 'ip': ip, 'ts': ts}, prev)

            block_index = None
            block_hash  = None
            if _blockchain is not None:
                try:
                    block = _blockchain.add_block({
                        'audit_id':    log_id,
                        'action':      action,
                        'user_email':  user_email,
                        'ip':          ip,
                        'status':      status,
                        'ts':          ts,
                        'db_row_hash': h,
                    })
                    block_index = block.index
                    block_hash  = block.hash
                except Exception as bc_err:
                    print(f'[Blockchain] Warning: failed to add block — {bc_err}')

            cur.execute(
                'INSERT INTO audit_logs'
                '(id,hash,prev_hash,action,user_email,user_id,ip,status,timestamp,block_index,block_hash) '
                'VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                (log_id, h, prev, action, user_email, user_id, ip, status, ts, block_index, block_hash)
            )
        db.commit()
    except Exception:
        db.rollback()
        raise

def _get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()

# ── API: Auth ──────────────────────────────────────────────────────────────────

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or {}
    email    = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    db = get_db()
    ip = _get_client_ip()

    try:
        with _cur(db) as cur:
            cur.execute('SELECT * FROM users WHERE lower(email)=%s', (email,))
            user = cur.fetchone()

        password_ok = user and _verify_pw(user['password_hash'], password)
        if not password_ok:
            _write_audit('Login Failed (Invalid Credentials)', email, ip, 'Flagged')
            return jsonify({'error': 'Invalid credentials'}), 401

        # Silent bcrypt migration for legacy SHA-256 hashes
        if _is_sha256_hash(user['password_hash']):
            try:
                with _cur(db) as cur:
                    cur.execute('UPDATE users SET password_hash=%s WHERE id=%s',
                                (_hash_pw(password), user['id']))
                db.commit()
            except Exception:
                db.rollback()
                raise

        if user['status'] == 'suspended':
            _write_audit('Login Blocked (Account Suspended)', email, ip, 'Flagged', user['id'])
            return jsonify({'error': 'Account suspended. Contact administrator.'}), 403

        if user['status'] == 'pending':
            _write_audit('Login Blocked (Account Pending Approval)', email, ip, 'Flagged', user['id'])
            return jsonify({'error': 'Account pending administrator approval.'}), 403

        mfa_required = bool(user['mfa_enabled'])
        if mfa_required:
            temp_token = create_token(user['id'], user['role'], user['email'], expiry_hours=0.17, token_type='mfa')
            try:
                _issue_email_otp(db, user, temp_token)
            except RuntimeError:
                _write_audit('Login Failed (MFA Email Not Configured)', user['email'], ip, 'Flagged', user['id'])
                return jsonify({'error': 'Email verification is not configured. Contact your administrator.'}), 503
            except Exception:
                _write_audit('Login Failed (MFA Email Delivery Failed)', user['email'], ip, 'Flagged', user['id'])
                return jsonify({'error': 'Could not send verification code. Please try again.'}), 503
            _write_audit('Login Step 1 Passed (Email MFA Code Sent)', user['email'], ip, 'Verified', user['id'])
            return jsonify({
                'mfa_required': True,
                'temp_token': temp_token,
                'name': user['name'],
                'masked_email': _mask_email(user['email']),
                'expires_in_minutes': MFA_OTP_TTL_MINUTES,
                'resend_after_seconds': MFA_OTP_RESEND_SECONDS,
            })

        # MFA disabled — issue full session token
        _write_audit('Login Success (MFA Disabled)', user['email'], ip, 'Verified', user['id'])
        try:
            with _cur(db) as cur:
                cur.execute('UPDATE users SET last_login=%s WHERE id=%s',
                            (datetime.datetime.utcnow().strftime('%b %d, %Y %I:%M %p'), user['id']))
            session_id, token_jti, csrf_token, expires_at = _create_session(db, user, ip)
            db.commit()
        except Exception:
            db.rollback()
            raise

        token = create_token(user['id'], user['role'], user['email'], session_id=session_id, jti=token_jti, expires_at=expires_at)
        return _session_cookie_response({'mfa_required': False, 'user': _user_dict(user), 'csrf_token': csrf_token}, token=token)

    except Exception:
        db.rollback()
        raise


@app.route('/api/auth/verify-mfa', methods=['POST'])
def api_verify_mfa():
    data       = request.get_json(silent=True) or {}
    temp_token = data.get('temp_token') or ''
    code       = (data.get('code') or '').strip()

    try:
        claims = jwt.decode(temp_token, SECRET_KEY, algorithms=['HS256'])
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Session expired. Please login again.'}), 401
    if claims.get('type') != 'mfa':
        return jsonify({'error': 'Invalid verification session.'}), 401

    db = get_db()
    with _cur(db) as cur:
        cur.execute('SELECT * FROM users WHERE id=%s', (claims['sub'],))
        user = cur.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 401

    ip = _get_client_ip()
    if len(code) != 6 or not code.isdigit():
        _write_audit('Login Failed (Malformed MFA Code)', user['email'], ip, 'Flagged', user['id'])
        return jsonify({'error': 'MFA code must be exactly 6 digits.'}), 400

    try:
        temp_token_hash = _hash_mfa_temp_token(temp_token)
        with _cur(db) as cur:
            cur.execute(
                'SELECT *, (expires_at <= NOW()) AS expired FROM mfa_email_otps '
                'WHERE user_id=%s AND temp_token_hash=%s AND used=FALSE ORDER BY created_at DESC LIMIT 1',
                (user['id'], temp_token_hash)
            )
            otp_row = cur.fetchone()

        if not otp_row:
            _write_audit('Login Failed (No Active MFA Code)', user['email'], ip, 'Flagged', user['id'])
            return jsonify({'error': 'Invalid or expired code.'}), 400

        if otp_row['expired']:
            with _cur(db) as cur:
                cur.execute('UPDATE mfa_email_otps SET used=TRUE WHERE id=%s', (otp_row['id'],))
            db.commit()
            _write_audit('Login Failed (Expired MFA Code)', user['email'], ip, 'Flagged', user['id'])
            return jsonify({'error': 'Invalid or expired code.'}), 400

        if otp_row['attempts'] >= MFA_OTP_MAX_ATTEMPTS:
            with _cur(db) as cur:
                cur.execute('UPDATE mfa_email_otps SET used=TRUE WHERE id=%s', (otp_row['id'],))
            db.commit()
            _write_audit('Login Failed (MFA Attempts Exceeded)', user['email'], ip, 'Flagged', user['id'])
            return jsonify({'error': 'Too many verification attempts. Please request a new code.'}), 429

        expected_hash = _hash_otp(user['id'], temp_token, code)
        if not hmac.compare_digest(otp_row['code_hash'], expected_hash):
            attempts = int(otp_row['attempts']) + 1
            lock_code = attempts >= MFA_OTP_MAX_ATTEMPTS
            with _cur(db) as cur:
                cur.execute('UPDATE mfa_email_otps SET attempts=%s, used=%s WHERE id=%s',
                            (attempts, lock_code, otp_row['id']))
            db.commit()
            _write_audit('Login Failed (Invalid MFA Code)', user['email'], ip, 'Flagged', user['id'])
            if lock_code:
                return jsonify({'error': 'Too many verification attempts. Please request a new code.'}), 429
            return jsonify({'error': 'Invalid or expired code.'}), 400

        last_login = datetime.datetime.utcnow().strftime('%b %d, %Y %I:%M %p')
        with _cur(db) as cur:
            cur.execute('UPDATE mfa_email_otps SET used=TRUE WHERE id=%s', (otp_row['id'],))
            cur.execute('UPDATE users SET last_login=%s WHERE id=%s', (last_login, user['id']))
            session_id, token_jti, csrf_token, expires_at = _create_session(db, user, ip)
        db.commit()
    except Exception:
        db.rollback()
        raise

    user['last_login'] = last_login
    token = create_token(user['id'], user['role'], user['email'], session_id=session_id, jti=token_jti, expires_at=expires_at)
    _write_audit('Login Success (Email MFA Verified)', user['email'], ip, 'Verified', user['id'])
    return _session_cookie_response({'user': _user_dict(user), 'csrf_token': csrf_token}, token=token)


@app.route('/api/auth/logout', methods=['POST'])
@require_auth()
def api_logout():
    db = get_db()
    try:
        with _cur(db) as cur:
            cur.execute(
                "UPDATE sessions SET status='Terminated', terminated_at=NOW() WHERE id=%s AND user_id=%s",
                (g.token_data['sid'], g.token_data['sub'])
            )
        db.commit()
    except Exception:
        db.rollback()
        raise
    _write_audit('Logout', g.token_data['email'], _get_client_ip(), 'Verified', g.token_data['sub'])
    return _session_cookie_response({'ok': True}, clear=True)


@app.route('/api/auth/logout-all', methods=['POST'])
@require_auth()
def api_logout_all():
    db = get_db()
    try:
        _terminate_user_sessions(db, g.token_data['sub'])
        db.commit()
    except Exception:
        db.rollback()
        raise
    _write_audit('Logout All Sessions', g.token_data['email'], _get_client_ip(), 'Verified', g.token_data['sub'])
    return _session_cookie_response({'ok': True}, clear=True)


@app.route('/api/auth/me', methods=['GET'])
@require_auth()
def api_me():
    db = get_db()
    with _cur(db) as cur:
        cur.execute('SELECT * FROM users WHERE id=%s', (g.token_data['sub'],))
        user = cur.fetchone()
    return jsonify({'user': _user_dict(user)})


@app.route('/api/auth/resend-mfa', methods=['POST'])
def api_resend_mfa():
    data = request.get_json(silent=True) or {}
    temp_token = data.get('temp_token') or ''
    try:
        claims = jwt.decode(temp_token, SECRET_KEY, algorithms=['HS256'])
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Session expired. Please login again.'}), 401
    if claims.get('type') != 'mfa':
        return jsonify({'error': 'Invalid verification session.'}), 401

    db = get_db()
    with _cur(db) as cur:
        cur.execute('SELECT * FROM users WHERE id=%s', (claims['sub'],))
        user = cur.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 401
    if not bool(user['mfa_enabled']):
        return jsonify({'error': 'MFA is not enabled for this account.'}), 400

    ip = _get_client_ip()
    temp_token_hash = _hash_mfa_temp_token(temp_token)
    with _cur(db) as cur:
        cur.execute(
            'SELECT EXTRACT(EPOCH FROM (NOW() - created_at)) AS age_seconds '
            'FROM mfa_email_otps WHERE user_id=%s AND temp_token_hash=%s ORDER BY created_at DESC LIMIT 1',
            (user['id'], temp_token_hash)
        )
        latest = cur.fetchone()
    if latest and latest['age_seconds'] is not None and float(latest['age_seconds']) < MFA_OTP_RESEND_SECONDS:
        retry_after = MFA_OTP_RESEND_SECONDS - int(float(latest['age_seconds']))
        return jsonify({'error': f'Please wait {retry_after} seconds before requesting another code.', 'retry_after': retry_after}), 429

    try:
        _issue_email_otp(db, user, temp_token)
    except RuntimeError:
        _write_audit('MFA Code Resend Failed (Email Not Configured)', user['email'], ip, 'Flagged', user['id'])
        return jsonify({'error': 'Email verification is not configured. Contact your administrator.'}), 503
    except Exception:
        _write_audit('MFA Code Resend Failed (Email Delivery Failed)', user['email'], ip, 'Flagged', user['id'])
        return jsonify({'error': 'Could not send verification code. Please try again.'}), 503

    _write_audit('MFA Code Resent', user['email'], ip, 'Verified', user['id'])
    return jsonify({
        'ok': True,
        'masked_email': _mask_email(user['email']),
        'expires_in_minutes': MFA_OTP_TTL_MINUTES,
        'resend_after_seconds': MFA_OTP_RESEND_SECONDS,
    })


@app.route('/api/auth/register', methods=['POST'])
def api_register():
    data     = request.get_json(silent=True) or {}
    name     = (data.get('name') or '').strip()
    email    = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    role     = data.get('role', 'patient')
    if not name or not email or not password:
        return jsonify({'error': 'Name, email and password required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if role not in ('admin', 'doctor', 'patient', 'staff'):
        role = 'patient'

    db     = get_db()
    new_id = 'u_' + secrets.token_hex(6)
    try:
        with _cur(db) as cur:
            cur.execute(
                'INSERT INTO users(id,name,email,password_hash,role,status,mfa_enabled) '
                'VALUES(%s,%s,%s,%s,%s,%s,%s)',
                (new_id, name, email, _hash_pw(password), role, 'pending', 1)
            )
        db.commit()
    except psycopg2.errors.UniqueViolation:
        db.rollback()
        return jsonify({'error': 'Email already registered'}), 409
    except Exception:
        db.rollback()
        raise

    _write_audit(f'Registration Request ({name}, {role})', email, _get_client_ip(), 'Verified')
    return jsonify({'ok': True, 'message': 'Registration submitted. Await admin approval.'}), 201


@app.route('/api/auth/password', methods=['PUT'])
@require_auth()
def api_change_password():
    data   = request.get_json(silent=True) or {}
    current_pw = data.get('current_password') or ''
    new_pw = data.get('new_password') or ''
    if not current_pw:
        return jsonify({'error': 'Current password is required'}), 400
    if len(new_pw) < 12:
        return jsonify({'error': 'Password must be at least 12 characters'}), 400

    db = get_db()
    with _cur(db) as cur:
        cur.execute('SELECT password_hash FROM users WHERE id=%s', (g.token_data['sub'],))
        user = cur.fetchone()
    if not user or not _verify_pw(user['password_hash'], current_pw):
        _write_audit('Password Change Failed (Invalid Current Password)', g.token_data['email'], _get_client_ip(), 'Flagged', g.token_data['sub'])
        return jsonify({'error': 'Current password is incorrect'}), 401
    try:
        with _cur(db) as cur:
            cur.execute('UPDATE users SET password_hash=%s WHERE id=%s',
                        (_hash_pw(new_pw), g.token_data['sub']))
        _terminate_user_sessions(db, g.token_data['sub'], except_session_id=g.token_data.get('sid'))
        db.commit()
    except Exception:
        db.rollback()
        raise

    _write_audit('Password Changed', g.token_data['email'], _get_client_ip(), 'Verified', g.token_data['sub'])
    return jsonify({'ok': True})


@app.route('/api/auth/mfa', methods=['PUT'])
@require_auth()
def api_update_own_mfa():
    data = request.get_json(silent=True) or {}
    if 'mfaEnabled' not in data:
        return jsonify({'error': 'mfaEnabled is required'}), 400

    enabled = 1 if data.get('mfaEnabled') else 0
    db = get_db()
    try:
        with _cur(db) as cur:
            cur.execute('UPDATE users SET mfa_enabled=%s WHERE id=%s', (enabled, g.token_data['sub']))
        _terminate_user_sessions(db, g.token_data['sub'], except_session_id=g.token_data.get('sid'))
        db.commit()
    except Exception:
        db.rollback()
        raise

    action = 'MFA Enabled' if enabled else 'MFA Disabled'
    _write_audit(action, g.token_data['email'], _get_client_ip(), 'Verified', g.token_data['sub'])
    with _cur(db) as cur:
        cur.execute('SELECT * FROM users WHERE id=%s', (g.token_data['sub'],))
        user = cur.fetchone()
    return jsonify(_user_dict(user))

# ── API: Users ─────────────────────────────────────────────────────────────────

def _user_dict(row):
    return {
        'id': row['id'], 'name': row['name'], 'email': row['email'],
        'role': row['role'], 'status': row['status'],
        'mfaEnabled': bool(row['mfa_enabled']),
        'lastLogin': row['last_login'] or 'Never',
        'department': row['department'],
    }

@app.route('/api/users', methods=['GET'])
@require_auth(roles=['admin'])
def api_get_users():
    db = get_db()
    with _cur(db) as cur:
        cur.execute('SELECT * FROM users ORDER BY name')
        rows = cur.fetchall()
    return jsonify([_user_dict(r) for r in rows])

@app.route('/api/users', methods=['POST'])
@require_auth(roles=['admin'])
def api_create_user():
    data  = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    name  = (data.get('name') or '').strip()
    role  = data.get('role', 'staff')
    dept  = data.get('department', '')
    if not email or not name:
        return jsonify({'error': 'Name and email required'}), 400

    db     = get_db()
    new_id = 'u_' + secrets.token_hex(6)
    try:
        with _cur(db) as cur:
            cur.execute(
                'INSERT INTO users(id,name,email,password_hash,role,status,mfa_enabled,department) '
                'VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',
                (new_id, name, email, _hash_pw('TempPass123!'), role, 'pending', 1, dept)
            )
        db.commit()
    except psycopg2.errors.UniqueViolation:
        db.rollback()
        return jsonify({'error': 'Email already exists'}), 409
    except Exception:
        db.rollback()
        raise

    _write_audit(f'User Created ({name})', g.token_data['email'], _get_client_ip(), 'Verified', g.token_data['sub'])
    with _cur(db) as cur:
        cur.execute('SELECT * FROM users WHERE id=%s', (new_id,))
        user = cur.fetchone()
    return jsonify(_user_dict(user)), 201

@app.route('/api/users/<uid>', methods=['PUT'])
@require_auth(roles=['admin'])
def api_update_user(uid):
    data = request.get_json(silent=True) or {}
    db   = get_db()

    with _cur(db) as cur:
        cur.execute('SELECT * FROM users WHERE id=%s', (uid,))
        user = cur.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    updates, params = [], []
    if 'status' in data:
        updates.append('status=%s');      params.append(data['status'])
    if 'mfaEnabled' in data:
        updates.append('mfa_enabled=%s'); params.append(1 if data['mfaEnabled'] else 0)
    if 'role' in data:
        updates.append('role=%s');        params.append(data['role'])
    if 'department' in data:
        updates.append('department=%s'); params.append(data['department'])

    if updates:
        try:
            with _cur(db) as cur:
                params.append(uid)
                cur.execute(f"UPDATE users SET {', '.join(updates)} WHERE id=%s", params)
            if 'status' in data or 'role' in data or 'mfaEnabled' in data:
                _terminate_user_sessions(db, uid)
            db.commit()
        except Exception:
            db.rollback()
            raise

    _write_audit(f'User Updated ({user["name"]})', g.token_data['email'], _get_client_ip(), 'Verified', g.token_data['sub'])
    with _cur(db) as cur:
        cur.execute('SELECT * FROM users WHERE id=%s', (uid,))
        updated = cur.fetchone()
    return jsonify(_user_dict(updated))

@app.route('/api/users/<uid>', methods=['DELETE'])
@require_auth(roles=['admin'])
def api_delete_user(uid):
    db = get_db()
    with _cur(db) as cur:
        cur.execute('SELECT * FROM users WHERE id=%s', (uid,))
        user = cur.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    try:
        _terminate_user_sessions(db, uid)
        with _cur(db) as cur:
            cur.execute('DELETE FROM users WHERE id=%s', (uid,))
        db.commit()
    except Exception:
        db.rollback()
        raise

    _write_audit(f'User Deleted ({user["name"]})', g.token_data['email'], _get_client_ip(), 'Verified', g.token_data['sub'])
    return jsonify({'ok': True})

# ── API: Patients ──────────────────────────────────────────────────────────────

def _patient_dict(row):
    return {
        'id': row['id'], 'name': row['name'], 'age': row['age'],
        'condition': row['condition'], 'lastVisit': row['last_visit'],
        'status': row['status'], 'doctorId': row['doctor_id'],
        'consentFlag': bool(row['consent_flag']),
    }

@app.route('/api/patients', methods=['GET'])
@require_auth(roles=['admin','doctor','staff'])
def api_get_patients():
    db   = get_db()
    role = g.token_data.get('role')
    with _cur(db) as cur:
        if role == 'doctor':
            cur.execute('SELECT * FROM patients WHERE doctor_id=%s ORDER BY name', (g.token_data['sub'],))
        else:
            cur.execute('SELECT * FROM patients ORDER BY name')
        rows = cur.fetchall()
    _write_audit('Viewed Patient List', g.token_data['email'], _get_client_ip(), 'Verified', g.token_data['sub'])
    return jsonify([_patient_dict(r) for r in rows])

@app.route('/api/patients/<pid>', methods=['GET'])
@require_auth(roles=['admin','doctor','staff'])
def api_get_patient(pid):
    db   = get_db()
    role = g.token_data.get('role')
    with _cur(db) as cur:
        if role == 'doctor':
            cur.execute('SELECT * FROM patients WHERE id=%s AND doctor_id=%s', (pid, g.token_data['sub']))
        else:
            cur.execute('SELECT * FROM patients WHERE id=%s', (pid,))
        row = cur.fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    _write_audit(f'Accessed Patient Record ({pid})', g.token_data['email'], _get_client_ip(), 'Verified', g.token_data['sub'])
    return jsonify(_patient_dict(row))

# ── API: Audit Logs ────────────────────────────────────────────────────────────

def _log_dict(row):
    return {
        'id':         row['id'],
        'hash':       row['hash'],
        'prevHash':   row['prev_hash'],
        'action':     row['action'],
        'user':       row['user_email'],
        'ip':         row['ip'],
        'status':     row['status'],
        'timestamp':  str(row['timestamp']),
        'blockIndex': row['block_index'] if row.get('block_index') is not None else None,
        'blockHash':  row['block_hash']  if row.get('block_hash')  else None,
    }

@app.route('/api/audit-logs', methods=['GET'])
@require_auth()
def api_get_logs():
    db    = get_db()
    role  = g.token_data.get('role')
    email = g.token_data.get('email')
    limit  = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))

    with _cur(db) as cur:
        if role == 'admin':
            cur.execute('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT %s OFFSET %s', (limit, offset))
            rows = cur.fetchall()
            cur.execute('SELECT COUNT(*) AS c FROM audit_logs')
        else:
            cur.execute('SELECT * FROM audit_logs WHERE user_email=%s ORDER BY timestamp DESC LIMIT %s OFFSET %s',
                        (email, limit, offset))
            rows = cur.fetchall()
            cur.execute('SELECT COUNT(*) AS c FROM audit_logs WHERE user_email=%s', (email,))
        total = cur.fetchone()['c']

    return jsonify({'logs': [_log_dict(r) for r in rows], 'total': total})

@app.route('/api/audit-logs/verify', methods=['GET'])
@require_auth(roles=['admin'])
def api_verify_chain():
    db = get_db()
    with _cur(db) as cur:
        cur.execute('SELECT * FROM audit_logs ORDER BY timestamp ASC')
        rows = cur.fetchall()

    broken, prev = [], ''
    for row in rows:
        expected = _make_hash({
            'id': row['id'], 'action': row['action'],
            'user': row['user_email'], 'ip': row['ip'],
            'ts': str(row['timestamp'])
        }, prev)
        if row['hash'] != expected:
            broken.append(row['id'])
        prev = row['hash']

    bc_summary = None
    if _blockchain is not None:
        bc_valid, bc_issues = _blockchain.is_chain_valid()
        bc_summary = {
            'valid':        bc_valid,
            'total_blocks': len(_blockchain.chain),
            'issues':       bc_issues,
            'anchor_intact': _blockchain._verify_anchor(),
        }

    return jsonify({
        'valid':       len(broken) == 0,
        'broken':      broken,
        'total':       len(rows),
        'blockchain':  bc_summary,
    })


@app.route('/api/blockchain/chain', methods=['GET'])
@require_auth(roles=['admin'])
def api_blockchain_chain():
    if _blockchain is None:
        return jsonify({'error': 'Blockchain not initialised'}), 503
    limit  = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))
    chain  = _blockchain.get_chain_dict()
    total  = len(chain)
    page   = list(reversed(chain))[offset: offset + limit]
    return jsonify({
        'blocks':       page,
        'total':        total,
        'public_key':   _blockchain.get_public_key_pem(),
    })


@app.route('/api/blockchain/verify', methods=['GET'])
@require_auth(roles=['admin'])
def api_blockchain_verify():
    if _blockchain is None:
        return jsonify({'error': 'Blockchain not initialised'}), 503
    valid, issues = _blockchain.is_chain_valid()
    checks_run = [
        'anchor_integrity',
        'sequential_index',
        'hash_integrity',
        'chain_linkage',
        'timestamp_monotonicity',
        'proof_of_work',
        'ecdsa_signature',
    ]
    return jsonify({
        'valid':         valid,
        'total_blocks':  len(_blockchain.chain),
        'issues':        issues,
        'anchor_intact': _blockchain._verify_anchor(),
        'checks_run':    checks_run,
        'message':       'Chain intact — all blocks verified' if valid else 'TAMPERING DETECTED',
    })


@app.route('/api/blockchain/public-key', methods=['GET'])
@require_auth(roles=['admin'])
def api_blockchain_public_key():
    if _blockchain is None:
        return jsonify({'error': 'Blockchain not initialised'}), 503
    pem = _blockchain.get_public_key_pem()
    return jsonify({
        'algorithm':  'ECDSA secp256k1',
        'usage':      'Verifies ECDSA signatures on every blockchain block',
        'public_key': pem,
        'note':       'Private key is stored server-side only and never exposed to clients.',
    })


@app.route('/api/blockchain/tamper-demo', methods=['POST'])
@require_auth(roles=['admin'])
def api_blockchain_tamper_demo():
    """
    Presentation demo only — simulates in-memory tampering on a chosen block
    and runs full verification to show which checks catch it.
    The real persisted chain is NEVER modified.
    """
    if _blockchain is None:
        return jsonify({'error': 'Blockchain not initialised'}), 503
    if len(_blockchain.chain) < 2:
        return jsonify({'error': 'Need at least 2 blocks to simulate tampering'}), 400

    data          = request.get_json(silent=True) or {}
    target_index  = int(data.get('block_index', 1))

    try:
        result = _blockchain.simulate_tamper(target_index)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    return jsonify(result)

# ── API: Sessions ──────────────────────────────────────────────────────────────

def _sess_dict(row):
    return {
        'id': row['id'], 'device': row['device'], 'ip': row['ip'],
        'location': row['location'], 'status': row['status'],
        'startedAt': str(row['created_at']),
        'expiresAt': str(row['expires_at']) if row.get('expires_at') else None,
        'lastSeenAt': str(row['last_seen_at']) if row.get('last_seen_at') else None,
        'current': row.get('id') == getattr(g, 'token_data', {}).get('sid'),
    }

@app.route('/api/sessions', methods=['GET'])
@require_auth(roles=['admin'])
def api_get_sessions():
    db = get_db()
    with _cur(db) as cur:
        cur.execute('SELECT * FROM sessions ORDER BY created_at DESC LIMIT 50')
        rows = cur.fetchall()
    return jsonify([_sess_dict(r) for r in rows])

@app.route('/api/auth/sessions', methods=['GET'])
@require_auth()
def api_get_own_sessions():
    db = get_db()
    with _cur(db) as cur:
        cur.execute('SELECT * FROM sessions WHERE user_id=%s ORDER BY created_at DESC LIMIT 25', (g.token_data['sub'],))
        rows = cur.fetchall()
    return jsonify([_sess_dict(r) for r in rows])

@app.route('/api/auth/sessions/<sid>', methods=['DELETE'])
@require_auth()
def api_terminate_own_session(sid):
    db = get_db()
    with _cur(db) as cur:
        cur.execute('SELECT * FROM sessions WHERE id=%s AND user_id=%s', (sid, g.token_data['sub']))
        sess = cur.fetchone()
    if not sess:
        return jsonify({'error': 'Not found'}), 404
    try:
        with _cur(db) as cur:
            cur.execute("UPDATE sessions SET status='Terminated', terminated_at=NOW() WHERE id=%s AND user_id=%s", (sid, g.token_data['sub']))
        db.commit()
    except Exception:
        db.rollback()
        raise
    _write_audit(f'Own Session Terminated ({sess["device"]})', g.token_data['email'], _get_client_ip(), 'Verified', g.token_data['sub'])
    if sid == g.token_data.get('sid'):
        return _session_cookie_response({'ok': True}, clear=True)
    return jsonify({'ok': True})

@app.route('/api/sessions/<sid>', methods=['DELETE'])
@require_auth(roles=['admin'])
def api_terminate_session(sid):
    db = get_db()
    with _cur(db) as cur:
        cur.execute('SELECT * FROM sessions WHERE id=%s', (sid,))
        sess = cur.fetchone()
    if not sess:
        return jsonify({'error': 'Not found'}), 404

    try:
        with _cur(db) as cur:
            cur.execute("UPDATE sessions SET status='Terminated', terminated_at=NOW() WHERE id=%s", (sid,))
        db.commit()
    except Exception:
        db.rollback()
        raise

    _write_audit(f'Session Terminated ({sess["device"]})', g.token_data['email'], _get_client_ip(), 'Verified', g.token_data['sub'])
    return jsonify({'ok': True})

# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_device(ua):
    ua = ua.lower()
    if 'iphone' in ua:                        device = 'iPhone'
    elif 'ipad' in ua:                        device = 'iPad'
    elif 'android' in ua:                     device = 'Android Device'
    elif 'macintosh' in ua or 'mac os' in ua: device = 'Mac'
    elif 'windows' in ua:                     device = 'Windows PC'
    else:                                     device = 'Unknown Device'
    if 'firefox' in ua:                       browser = '(Firefox)'
    elif 'chrome' in ua and 'safari' in ua:   browser = '(Chrome)'
    elif 'safari' in ua:                      browser = '(Safari)'
    elif 'edge' in ua:                        browser = '(Edge)'
    else:                                     browser = '(Browser)'
    return f'{device} {browser}'

# ── Google OAuth ──────────────────────────────────────────────────────────────

# Simple in-memory rate limiter for the OAuth callback: max 10 attempts per IP
# per 5-minute window. Resets on restart (acceptable for this use-case).
_oauth_rate: dict = {}
_OAUTH_RATE_MAX    = 10
_OAUTH_RATE_WINDOW = 300  # seconds


def _oauth_check_rate(ip: str) -> bool:
    """Return True if the request is allowed, False if rate-limited."""
    now   = datetime.datetime.utcnow().timestamp()
    entry = _oauth_rate.get(ip)
    if entry is None or now - entry['ts'] > _OAUTH_RATE_WINDOW:
        _oauth_rate[ip] = {'ts': now, 'count': 1}
        return True
    entry['count'] += 1
    return entry['count'] <= _OAUTH_RATE_MAX


def _google_redirect_uri():
    proto = request.headers.get('X-Forwarded-Proto') or ('https' if request.is_secure else 'http')
    host  = request.headers.get('X-Forwarded-Host') or request.host
    return f'{proto}://{host}/auth/google/callback'


def _verify_google_id_token(id_token: str) -> dict | None:
    """
    Validate Google ID token via Google's tokeninfo endpoint.
    Checks: signature (server-side), aud, iss, exp, email_verified.
    Returns the claims dict on success, None on any failure.
    """
    try:
        resp = _requests.get(
            'https://oauth2.googleapis.com/tokeninfo',
            params={'id_token': id_token},
            timeout=10
        )
    except Exception:
        return None

    if not resp.ok:
        return None

    claims = resp.json()

    # ① Verify audience matches our client ID
    if claims.get('aud') != GOOGLE_CLIENT_ID:
        return None

    # ② Verify issuer is Google
    if claims.get('iss') not in ('accounts.google.com', 'https://accounts.google.com'):
        return None

    # ③ Token must not be expired (Google already checks this, belt-and-suspenders)
    try:
        if int(claims.get('exp', 0)) < int(datetime.datetime.utcnow().timestamp()):
            return None
    except (ValueError, TypeError):
        return None

    # ④ Email must be verified by Google
    if claims.get('email_verified') not in (True, 'true'):
        return None

    return claims


@app.route('/auth/google')
def google_oauth_start():
    if not GOOGLE_CLIENT_ID:
        return redirect('/login?error=google_not_configured')
    state  = secrets.token_urlsafe(16)
    params = urlencode({
        'client_id':     GOOGLE_CLIENT_ID,
        'redirect_uri':  _google_redirect_uri(),
        'response_type': 'code',
        'scope':         'openid email profile',
        'state':         state,
        'access_type':   'online',
    })
    resp = redirect(f'https://accounts.google.com/o/oauth2/v2/auth?{params}')
    resp.set_cookie('google_oauth_state', state, max_age=600, httponly=True,
                    samesite='Lax', secure=request.is_secure)
    return resp


@app.route('/auth/google/callback')
def google_oauth_callback():
    ip = _get_client_ip()

    # ── Rate limiting ──────────────────────────────────────────────────────────
    if not _oauth_check_rate(ip):
        _write_audit('Google SSO Failed (Rate Limited)', 'unknown', ip, 'Flagged')
        return redirect('/login?error=rate_limited')

    if request.args.get('error'):
        _write_audit('Google SSO Denied (User Cancelled)', 'unknown', ip, 'Flagged')
        return redirect('/login?error=google_denied')

    # ── CSRF state check ───────────────────────────────────────────────────────
    state_cookie = request.cookies.get('google_oauth_state', '')
    state_param  = request.args.get('state', '')
    if not state_cookie or not hmac.compare_digest(state_cookie, state_param):
        _write_audit('Google SSO Failed (Invalid State)', 'unknown', ip, 'Flagged')
        return redirect('/login?error=oauth_state')

    code = request.args.get('code', '')
    if not code:
        return redirect('/login?error=google_denied')

    # ── Exchange code for tokens ───────────────────────────────────────────────
    try:
        token_resp = _requests.post('https://oauth2.googleapis.com/token', data={
            'code':          code,
            'client_id':     GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'redirect_uri':  _google_redirect_uri(),
            'grant_type':    'authorization_code',
        }, timeout=10)
    except Exception:
        return redirect('/login?error=google_token')

    if not token_resp.ok:
        _write_audit('Google SSO Failed (Token Exchange Error)', 'unknown', ip, 'Flagged')
        return redirect('/login?error=google_token')

    token_data = token_resp.json()
    id_token   = token_data.get('id_token', '')

    if not id_token:
        _write_audit('Google SSO Failed (No ID Token)', 'unknown', ip, 'Flagged')
        return redirect('/login?error=google_token')

    # ── Validate ID token: signature, aud, iss, exp, email_verified ───────────
    claims = _verify_google_id_token(id_token)
    if not claims:
        _write_audit('Google SSO Failed (Invalid ID Token)', 'unknown', ip, 'Flagged')
        return redirect('/login?error=google_token')

    # All identity data comes exclusively from the verified token — never from
    # query params, frontend, or unverified sources.
    google_id = claims.get('sub', '')
    email     = (claims.get('email') or '').strip().lower()
    name      = claims.get('name', '') or email.split('@')[0]
    picture   = claims.get('picture', '')

    if not email or not google_id:
        _write_audit('Google SSO Failed (Missing Claims)', 'unknown', ip, 'Flagged')
        return redirect('/login?error=google_email')

    db = get_db()

    with _cur(db) as cur:
        cur.execute('SELECT * FROM users WHERE google_id=%s LIMIT 1', (google_id,))
        user = cur.fetchone()

        if not user:
            # Look up by email only if no google_id match
            cur.execute('SELECT * FROM users WHERE lower(email)=%s LIMIT 1', (email,))
            user = cur.fetchone()

    def _clear_state(r):
        r.delete_cookie('google_oauth_state', path='/')
        return r

    if user:
        # ── Account linking protection ─────────────────────────────────────────
        # If a password-based account exists for this email, do NOT silently link
        # it to Google. Require the user to log in with their password.
        # Only allow Google login if the account was originally created via Google
        # (password_hash == '!google_sso!') or already has a google_id attached.
        already_linked = bool(user.get('google_id'))
        is_google_account = user.get('password_hash') == '!google_sso!'

        if not already_linked and not is_google_account:
            _write_audit('Google SSO Blocked (Account Linking Attempt)', email, ip, 'Flagged', user['id'])
            return _clear_state(redirect('/login?error=email_exists'))

        # Attach google_id if missing on a Google-created account
        if not already_linked and is_google_account:
            try:
                with _cur(db) as cur:
                    cur.execute('UPDATE users SET google_id=%s WHERE id=%s', (google_id, user['id']))
                db.commit()
            except Exception:
                db.rollback()

        if user['status'] == 'suspended':
            _write_audit('Google SSO Blocked (Account Suspended)', email, ip, 'Flagged', user['id'])
            return _clear_state(redirect('/login?error=suspended'))
        if user['status'] == 'pending':
            _write_audit('Google SSO Blocked (Account Pending)', email, ip, 'Flagged', user['id'])
            return _clear_state(redirect('/login?error=pending'))

        try:
            last_login = datetime.datetime.utcnow().strftime('%b %d, %Y %I:%M %p')
            with _cur(db) as cur:
                cur.execute('UPDATE users SET last_login=%s WHERE id=%s', (last_login, user['id']))
            session_id, token_jti, csrf_token, expires_at = _create_session(db, user, ip)
            db.commit()
        except Exception:
            db.rollback()
            raise

        access_token = create_token(user['id'], user['role'], user['email'],
                                    session_id=session_id, jti=token_jti, expires_at=expires_at)
        user_dict             = _user_dict(user)
        user_dict['lastLogin'] = last_login

        _write_audit('Login Success (Google SSO)', user['email'], ip, 'Verified', user['id'])

        resp = make_response(render_template(
            'google_success.html',
            user=json.dumps(user_dict),
            token=access_token,
            csrf_token=csrf_token,
            role=user['role']
        ))
        resp.set_cookie(AUTH_COOKIE_NAME, access_token,
                        max_age=int(ACCESS_TOKEN_HOURS * 3600),
                        path='/', samesite='Lax', secure=request.is_secure, httponly=True)
        return _clear_state(resp)

    else:
        # New user — store only minimal data (no access/refresh tokens)
        pending_token = jwt.encode({
            'type':      'google_pending',
            'google_id': google_id,
            'email':     email,
            'name':      name,
            'picture':   picture,
            'exp':       datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
            'iat':       datetime.datetime.utcnow(),
        }, SECRET_KEY, algorithm='HS256')

        _write_audit('Google SSO New User (Role Selection Pending)', email, ip, 'Verified')

        resp = redirect('/auth/google/complete')
        resp.set_cookie('google_pending', pending_token, max_age=900, httponly=True,
                        samesite='Lax', secure=request.is_secure)
        return _clear_state(resp)


@app.route('/auth/google/complete')
def google_oauth_complete_page():
    pending_token = request.cookies.get('google_pending', '')
    if not pending_token:
        return redirect('/register')
    try:
        claims = jwt.decode(pending_token, SECRET_KEY, algorithms=['HS256'])
    except jwt.InvalidTokenError:
        return redirect('/register')
    if claims.get('type') != 'google_pending':
        return redirect('/register')
    return render_template('google_complete.html',
                            name=claims.get('name', ''),
                            email=claims.get('email', ''),
                            picture=claims.get('picture', ''))


@app.route('/api/auth/google/complete', methods=['POST'])
def api_google_complete():
    pending_token = request.cookies.get('google_pending', '')
    if not pending_token:
        return jsonify({'error': 'No pending registration. Please sign in with Google again.'}), 400
    try:
        claims = jwt.decode(pending_token, SECRET_KEY, algorithms=['HS256'])
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Session expired. Please sign in with Google again.'}), 401
    if claims.get('type') != 'google_pending':
        return jsonify({'error': 'Invalid session.'}), 400

    data = request.get_json(silent=True) or {}
    role = (data.get('role') or '').strip()
    if role not in ('admin', 'doctor', 'patient', 'staff'):
        return jsonify({'error': 'Please select a valid role.'}), 400

    google_id = claims['google_id']
    email     = claims['email']
    name      = claims['name']

    db     = get_db()
    new_id = 'u_' + secrets.token_hex(6)
    ip     = _get_client_ip()

    try:
        with _cur(db) as cur:
            cur.execute(
                'INSERT INTO users(id,name,email,password_hash,role,status,mfa_enabled,google_id) '
                'VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',
                (new_id, name, email, '!google_sso!', role, 'pending', 1, google_id)
            )
        db.commit()
    except psycopg2.errors.UniqueViolation:
        db.rollback()
        return jsonify({'error': 'An account with this email already exists.'}), 409
    except Exception:
        db.rollback()
        raise

    _write_audit(f'Google Registration Request ({name}, {role})', email, ip, 'Verified')

    resp = make_response(jsonify({'ok': True}), 201)
    resp.delete_cookie('google_pending', path='/')
    return resp


# ── SPA Routes ─────────────────────────────────────────────────────────────────

@app.route('/')
def index(): return redirect('/login')

@app.route('/login')
def login(): return render_template('login.html')

@app.route('/register')
def register(): return render_template('register.html')

@app.route('/admin')
def admin(): return render_template('admin.html')

@app.route('/doctor')
def doctor(): return render_template('doctor.html')

@app.route('/patient')
def patient(): return render_template('patient.html')

@app.route('/staff')
def staff(): return render_template('staff.html')

@app.route('/security')
def security(): return render_template('security.html')

@app.route('/iam')
def iam(): return render_template('iam.html')

@app.route('/audit-logs')
def audit_logs(): return render_template('audit-logs.html')

@app.route('/settings')
def settings(): return render_template('settings.html')

@app.route('/blockchain')
def blockchain_explorer(): return render_template('blockchain.html')

# ── Boot ───────────────────────────────────────────────────────────────────────

with app.app_context():
    init_db()

# Initialise the blockchain singleton (after DB tables are created)
_blockchain = None
try:
    from blockchain import HealthcareBlockchain as _HC
    _blockchain = _HC(DATABASE_URL)
    print(f'[Blockchain] Ready — {len(_blockchain.chain)} block(s) loaded')
except Exception as _bc_init_err:
    print(f'[Blockchain] WARNING: could not initialise — {_bc_init_err}')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
