from flask import Flask, render_template, request
import bcrypt
import sqlite3
from database import init_db

app = Flask(__name__)
init_db()

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
            return f'Registered successfully! Your password hash is : {hashed} <br><br> <a href="/login">Login here</a>'
        except:
            return 'Username already exists!'

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?',
                           (username,)).fetchone()
        conn.close()

        if not user:
            return 'User not found!'

        if bcrypt.checkpw(password, user['password'].encode('utf-8')):  # comparing hash
            return 'Login successful!'
        else:
            return 'Incorrect credentials'

    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)