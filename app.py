from flask import Flask, render_template, redirect, request, jsonify, g
import psycopg2, psycopg2.extras, psycopg2.errors
import os, hashlib, json, jwt, datetime, functools, secrets, re, bcrypt

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

if not DATABASE_URL:
    raise RuntimeError(
        "SUPABASE_DB_URL is not set.\n"
        "  • Locally: create a .env file with SUPABASE_DB_URL=<your connection string>\n"
        "  • On Replit: add it under Secrets in the sidebar"
    )

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

# ── Audit Chain Hashing ───────────────────────────────────────────────────────

def _make_hash(data, prev_hash=''):
    payload = prev_hash + json.dumps(data, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()

# ── Database Initialisation ───────────────────────────────────────────────────

_SEED_PASSWORD = 'Guardian2024!'

def init_db():
    """
    Create tables + indexes and seed demo data exactly once.
    Uses a dedicated connection separate from Flask's per-request g.db.
    Seed guard: only inserts when users table is empty, so restarts are safe.
    ON CONFLICT DO NOTHING provides an extra safety net if the guard races.
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
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
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
            # audit_logs.user_email: used when non-admin users query their own logs.
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_logs_user_email
                ON audit_logs(user_email)
            """)

        conn.commit()

        # ── Seed guard ────────────────────────────────────────────────────────
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute('SELECT COUNT(*) AS c FROM users')
            if cur.fetchone()['c'] > 0:
                return  # already seeded — nothing to do

        seed_hash = _hash_pw(_SEED_PASSWORD)

        with conn.cursor() as cur:
            users = [
                ('u1','Dr. Sarah Admin',  'admin@guardian.health',   seed_hash,'admin',  'active',   1,'Oct 24, 2023 8:12 AM', 'IT Security'),
                ('u2','Dr. James Wilson', 'doctor@guardian.health',  seed_hash,'doctor', 'active',   1,'Oct 24, 2023 9:30 AM', 'Cardiology'),
                ('u3','Emily Chen',       'patient@guardian.health', seed_hash,'patient','active',   1,'Oct 23, 2023 2:45 PM', None),
                ('u4','Marcus Johnson',   'staff@guardian.health',   seed_hash,'staff',  'active',   0,'Oct 24, 2023 7:55 AM', 'Triage'),
                ('u5','Dr. Lisa Cuddy',   'lcuddy@guardian.health',  seed_hash,'doctor', 'active',   1,'Oct 24, 2023 8:45 AM', 'Endocrinology'),
                ('u6','Robert Chase',     'rc@guardian.health',      seed_hash,'staff',  'pending',  0,'Never',                'ICU'),
                ('u7','Gregory House',    'house@guardian.health',   seed_hash,'doctor', 'suspended',0,'Oct 1, 2023 11:20 AM', 'Diagnostics'),
                ('u8','Allison Cameron',  'acameron@guardian.health',seed_hash,'doctor', 'active',   1,'Oct 24, 2023 9:10 AM', 'Immunology'),
            ]
            for u in users:
                cur.execute(
                    'INSERT INTO users(id,name,email,password_hash,role,status,mfa_enabled,last_login,department) '
                    'VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING', u
                )

            patients = [
                ('p1','Emily Chen',    34,'Hypertension',              'Oct 15, 2023','Stable',    'u2',True),
                ('p2','Michael Scott', 45,'Type 2 Diabetes',           'Oct 20, 2023','Critical',  'u2',True),
                ('p3','Jim Halpert',   42,'Asthma',                    'Sep 05, 2023','Stable',    'u5',False),
                ('p4','Pam Beesly',    38,'Pregnancy (2nd Trimester)', 'Oct 22, 2023','Monitoring','u5',True),
            ]
            for p in patients:
                cur.execute(
                    'INSERT INTO patients(id,name,age,condition,last_visit,status,doctor_id,consent_flag) '
                    'VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING', p
                )

            raw_logs = [
                ('log1','Login Success',                      'admin@guardian.health', 'u1','192.168.1.45','Verified','Oct 24, 2023 8:12 AM'),
                ('log2','Accessed Patient Record (P1)',        'doctor@guardian.health','u2','10.0.0.12',  'Verified','Oct 24, 2023 9:35 AM'),
                ('log3','Failed Login (Invalid MFA)',          'staff@guardian.health', 'u4','45.22.11.90','Flagged', 'Oct 24, 2023 7:50 AM'),
                ('log4','Updated Prescription (P2)',           'doctor@guardian.health','u2','10.0.0.12',  'Verified','Oct 24, 2023 9:40 AM'),
                ('log5','Role Modified (u4 → Senior Staff)',  'admin@guardian.health', 'u1','192.168.1.45','Verified','Oct 24, 2023 10:05 AM'),
                ('log6','Document Downloaded (Report)',        'patient@guardian.health','u3','73.44.120.5','Verified','Oct 23, 2023 2:55 PM'),
            ]
            prev = ''
            for lid, action, email, uid, ip, status, ts in raw_logs:
                h = _make_hash({'id': lid, 'action': action, 'user': email, 'ip': ip, 'ts': ts}, prev)
                cur.execute(
                    'INSERT INTO audit_logs(id,hash,prev_hash,action,user_email,user_id,ip,status,timestamp) '
                    'VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING',
                    (lid, h, prev, action, email, uid, ip, status, ts)
                )
                prev = h

            sessions = [
                ('sess1','u1','MacBook Pro (Chrome)','192.168.1.45','New York, USA','Active',    'Oct 24, 2023 8:12 AM'),
                ('sess2','u1','iPhone 13 (Safari)',  '10.0.0.12',  'New York, USA','Active',    'Oct 24, 2023 9:30 AM'),
                ('sess3','u1','Windows PC (Edge)',   '45.22.11.90','Moscow, RU',   'Terminated','Oct 23, 2023 11:15 PM'),
            ]
            for s in sessions:
                cur.execute(
                    'INSERT INTO sessions(id,user_id,device,ip,location,status,created_at) '
                    'VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING', s
                )

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

# ── Auth Helpers ───────────────────────────────────────────────────────────────

def create_token(user_id, role, email, expiry_hours=24):
    payload = {
        'sub': user_id,
        'role': role,
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=expiry_hours),
        'iat': datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def require_auth(roles=None):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get('Authorization', '')
            if not auth.startswith('Bearer '):
                return jsonify({'error': 'No token'}), 401
            token = auth[7:]
            try:
                data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            if roles and data.get('role') not in roles:
                return jsonify({'error': 'Forbidden'}), 403
            g.token_data = data
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ── Audit Logging ─────────────────────────────────────────────────────────────

def _write_audit(action, user_email, ip='', status='Verified', user_id=None):
    """
    Append a tamper-evident audit log entry.
    Rolls back and re-raises on any DB error so the caller's transaction
    is not left in an aborted state.
    """
    db = get_db()
    try:
        with _cur(db) as cur:
            cur.execute('SELECT hash FROM audit_logs ORDER BY timestamp DESC LIMIT 1')
            last = cur.fetchone()
            prev = last['hash'] if last else ''
            log_id = 'log_' + secrets.token_hex(8)
            ts = datetime.datetime.utcnow().isoformat(sep=' ', timespec='seconds')
            h = _make_hash({'id': log_id, 'action': action, 'user': user_email, 'ip': ip, 'ts': ts}, prev)
            cur.execute(
                'INSERT INTO audit_logs(id,hash,prev_hash,action,user_email,user_id,ip,status,timestamp) '
                'VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                (log_id, h, prev, action, user_email, user_id, ip, status, ts)
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
            temp_token = create_token(user['id'], user['role'], user['email'], expiry_hours=0.05)
            _write_audit('Login Step 1 Passed (MFA Required)', user['email'], ip, 'Verified', user['id'])
            return jsonify({'mfa_required': True, 'temp_token': temp_token, 'name': user['name']})

        # MFA disabled — issue full session token
        _write_audit('Login Success (MFA Disabled)', user['email'], ip, 'Verified', user['id'])
        try:
            with _cur(db) as cur:
                cur.execute('UPDATE users SET last_login=%s WHERE id=%s',
                            (datetime.datetime.utcnow().strftime('%b %d, %Y %I:%M %p'), user['id']))
            db.commit()
        except Exception:
            db.rollback()
            raise

        token = create_token(user['id'], user['role'], user['email'])
        return jsonify({'mfa_required': False, 'token': token, 'user': _user_dict(user)})

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

    _write_audit('Login Failed (MFA Not Yet Implemented)', user['email'], ip, 'Flagged', user['id'])
    return jsonify({
        'error': 'MFA verification is not yet configured on this system. '
                 'Contact your administrator to enable access.'
    }), 501


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
    new_pw = data.get('new_password') or ''
    if len(new_pw) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    db = get_db()
    try:
        with _cur(db) as cur:
            cur.execute('UPDATE users SET password_hash=%s WHERE id=%s',
                        (_hash_pw(new_pw), g.token_data['sub']))
        db.commit()
    except Exception:
        db.rollback()
        raise

    _write_audit('Password Changed', g.token_data['email'], _get_client_ip(), 'Verified', g.token_data['sub'])
    return jsonify({'ok': True})

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
        'id': row['id'], 'hash': row['hash'], 'prevHash': row['prev_hash'],
        'action': row['action'], 'user': row['user_email'],
        'ip': row['ip'], 'status': row['status'], 'timestamp': str(row['timestamp']),
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

    return jsonify({'valid': len(broken) == 0, 'broken': broken, 'total': len(rows)})

# ── API: Sessions ──────────────────────────────────────────────────────────────

def _sess_dict(row):
    return {
        'id': row['id'], 'device': row['device'], 'ip': row['ip'],
        'location': row['location'], 'status': row['status'],
        'startedAt': str(row['created_at']),
    }

@app.route('/api/sessions', methods=['GET'])
@require_auth(roles=['admin'])
def api_get_sessions():
    db = get_db()
    with _cur(db) as cur:
        cur.execute('SELECT * FROM sessions ORDER BY created_at DESC LIMIT 50')
        rows = cur.fetchall()
    return jsonify([_sess_dict(r) for r in rows])

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
            cur.execute("UPDATE sessions SET status='Terminated' WHERE id=%s", (sid,))
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

# ── Boot ───────────────────────────────────────────────────────────────────────

with app.app_context():
    init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
