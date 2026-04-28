from flask import Flask, render_template, request, session, redirect, url_for
import bcrypt
import sqlite3
import pyotp
import qrcode
import io
import base64
from database_qr import init_db
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key_change_this'
init_db()

# Rate limiter setup
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Track failed attempts
failed_attempts = {}
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 10  # minutes

# Track used OTPs to prevent replay attacks
used_otps = {}

def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def generate_qr_code(username, secret):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="SecureLoginApp")
    qr = qrcode.make(uri)
    buffer = io.BytesIO()
    qr.save(buffer, format='PNG')
    buffer.seek(0)
    img_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return img_b64

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')

        # Generate TOTP secret for this user
        totp_secret = pyotp.random_base32()

        try:
            conn = get_db()
            conn.execute(
                'INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)',
                (username, hashed, totp_secret)
            )
            conn.commit()
            conn.close()

            # Generate QR code to show user
            qr_img = generate_qr_code(username, totp_secret)

            return render_template('setup_2fa.html',
                                   username=username,
                                   secret=totp_secret,
                                   qr_img=qr_img,
                                   password_hash=hashed)
        except:
            return 'Username already exists!'

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        # Check lockout
        if username in failed_attempts:
            attempts, lockout_time = failed_attempts[username]
            if attempts >= LOCKOUT_THRESHOLD:
                if datetime.now() < lockout_time:
                    remaining = (lockout_time - datetime.now()).seconds // 60
                    return f'Account locked! Try again in {remaining} minutes.'
                else:
                    del failed_attempts[username]

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if not user:
            return 'User not found!'

        if bcrypt.checkpw(password, user['password'].encode('utf-8')):
            if username in failed_attempts:
                del failed_attempts[username]
            # Password correct — store username in session, go to OTP step
            session['pending_2fa_user'] = username
            return redirect(url_for('verify_otp'))
        else:
            # Record failed attempt
            if username not in failed_attempts:
                failed_attempts[username] = [0, None]
            failed_attempts[username][0] += 1
            attempts = failed_attempts[username][0]

            if attempts >= LOCKOUT_THRESHOLD:
                failed_attempts[username][1] = datetime.now() + timedelta(minutes=LOCKOUT_DURATION)
                return f'Too many failed attempts! Account locked for {LOCKOUT_DURATION} minutes.'
            else:
                return f'Wrong password! {LOCKOUT_THRESHOLD - attempts} attempts remaining before lockout.'

    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    # Must have passed password step first
    if 'pending_2fa_user' not in session:
        return redirect(url_for('login'))

    username = session['pending_2fa_user']

    if request.method == 'POST':
        otp_entered = request.form['otp'].strip()

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        totp = pyotp.TOTP(user['totp_secret'])

        # Check replay — has this OTP been used before?
        otp_key = f"{username}:{otp_entered}"
        if otp_key in used_otps:
            return render_template('verify_otp.html', error='Replay attack detected! This OTP was already used.')

        # Verify OTP (valid_window=1 allows 30s grace)
        if totp.verify(otp_entered, valid_window=1):
            # Mark OTP as used to block replay
            used_otps[otp_key] = datetime.now()
            session.pop('pending_2fa_user', None)
            session['logged_in_user'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('verify_otp.html', error='Invalid OTP! Please try again.')

    return render_template('verify_otp.html', error=None)

@app.route('/dashboard')
def dashboard():
    if 'logged_in_user' not in session:
        return redirect(url_for('login'))
    username = session['logged_in_user']
    return f'''
        <div style="font-family:Segoe UI;text-align:center;margin-top:100px">
            <h2 style="color:#2e7d52">Welcome, {username}!</h2>
            <p>You are securely logged in with 2FA.</p>
            <a href="/logout" style="color:#2e7d52">Logout</a>
        </div>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)