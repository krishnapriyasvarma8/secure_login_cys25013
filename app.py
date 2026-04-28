from flask import Flask, render_template, request
import bcrypt
import sqlite3
from database import init_db
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta

app = Flask(__name__)
init_db()

# Rate limiter setup
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Track failed attempts
failed_attempts = {}
LOCKOUT_THRESHOLD = 5      # lock after 5 failed attempts
LOCKOUT_DURATION = 10      # lockout for 10 minutes

def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')

        try:
            conn = get_db()
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                        (username, hashed))
            conn.commit()
            conn.close()
            return f'Registered successfully! Your password hash is: {hashed} <br><br> <a href="/login">Login here</a>'
        except:
            return 'Username already exists!'

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # rate limiting
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        # Check if account is locked
        if username in failed_attempts:
            attempts, lockout_time = failed_attempts[username]
            if attempts >= LOCKOUT_THRESHOLD:
                if datetime.now() < lockout_time:
                    remaining = (lockout_time - datetime.now()).seconds // 60
                    return f'Account locked! Try again in {remaining} minutes.'
                else:
                    # Reset after lockout duration
                    del failed_attempts[username]

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?',
                           (username,)).fetchone()
        conn.close()

        if not user:
            return 'User not found!'

        if bcrypt.checkpw(password, user['password'].encode('utf-8')):
            # Reset failed attempts on successful login
            if username in failed_attempts:
                del failed_attempts[username]
            return 'Login successful!'
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

if __name__ == '__main__':
    app.run(debug=True)