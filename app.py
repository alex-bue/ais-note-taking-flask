import json, sqlite3, click, functools, os, hashlib, time, random, sys
from flask import Flask, current_app, g, session, redirect, render_template, url_for, request

### DATABASE FUNCTIONS ###

def connect_db():
    return sqlite3.connect(app.database)

def init_db():
    """Initializes the database with our great SQL schema"""
    conn = connect_db()
    db = conn.cursor()
    with open('schema.sql', 'r') as f:
        db.executescript(f.read())
    db.close()

### APPLICATION SETUP ###
app = Flask(__name__)
app.database = "db.sqlite3"
# Ensure a secure, random SECRET_KEY that stays the same across restarts by saving in an environment variable or file.
app.secret_key = 'a_secure_secret_key'

### ADMINISTRATOR'S PANEL ###
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

@app.route("/")
def index():
    if not session.get('logged_in'):
        return render_template('index.html')
    else:
        return redirect(url_for('notes'))

@app.route("/notes/", methods=('GET', 'POST'))
@login_required
def notes():
    importerror=""
    # Posting a new note:
    if request.method == 'POST':
        db = connect_db()
        c = db.cursor()
        if request.form['submit_button'] == 'add note':
            note = request.form['noteinput']
            # Use parameters to avoid SQL injection
            c.execute("INSERT INTO notes (assocUser, dateWritten, note, publicID) VALUES (?, ?, ?, ?);",
                      (session['userid'], time.strftime('%Y-%m-%d %H:%M:%S'), note, random.randint(1000000000, 9999999999)))
            db.commit()
        elif request.form['submit_button'] == 'import note':
            noteid = request.form['noteid']
            # Use parameters to avoid SQL injection
            c.execute("SELECT * from NOTES where publicID = ?", (noteid,))
            result = c.fetchone()
            if result:
                c.execute("INSERT INTO notes (assocUser, dateWritten, note, publicID) VALUES (?, ?, ?, ?);",
                          (session['userid'], result[2], result[3], result[4]))
                db.commit()
            else:
                importerror = "No such note with that ID!"
        db.close()

    # Retrieve user's notes
    db = connect_db()
    c = db.cursor()
    c.execute("SELECT * FROM notes WHERE assocUser = ?", (session['userid'],))
    notes = c.fetchall()
    db.close()

    return render_template('notes.html', notes=notes, importerror=importerror)

@app.route("/login/", methods=('GET', 'POST'))
def login():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = connect_db()
        c = db.cursor()
        # Hash and check the password securely
        c.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        if user and hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), user[1][:16], 100000) == user[1][16:]:
            session.clear()
            session['logged_in'] = True
            session['userid'] = user[0]
            session['username'] = username
            return redirect(url_for('index'))
        else:
            error = "Wrong username or password."
        db.close()
    return render_template('login.html', error=error)

@app.route("/register/", methods=('GET', 'POST'))
def register():
    errored = False
    usererror = ""
    passworderror = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = connect_db()
        c = db.cursor()
        # Check for existing username
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        if c.fetchone():
            errored = True
            usererror = "That username is already in use by someone else!"

        # Hash the password with a new, random salt
        if not errored:
            salt = os.urandom(16)
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            salted_hash = salt + password_hash
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, salted_hash))
            db.commit()
            db.close()
            return redirect(url_for('login'))
        db.close()
    return render_template('register.html', usererror=usererror, passworderror=passworderror)

@app.route("/logout/")
@login_required
def logout():
    """Logout: clears the session"""
    session.clear()
    return redirect(url_for('index'))

if __name__ == "__main__":
    # Create database if it doesn't exist yet
    if not os.path.exists(app.database):
        init_db()
    runport = 5000
    if len(sys.argv) == 2:
        runport = int(sys.argv[1])
    app.run(host='0.0.0.0', port=runport)  # runs on machine IP address to make it visible on the network

