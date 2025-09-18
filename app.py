from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, send
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

# --- App setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'  # for Flask sessions

# --- MongoDB Atlas connection ---
client = MongoClient("mongodb+srv://shreyashedge07_db_user:fjMKld8lhqSBnc3F@cluster0.181l3dr.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["chat_app_db"]  # database
users_collection = db["users"]  # collection for users

# --- Init SocketIO ---
socketio = SocketIO(app, cors_allowed_origins="*")

# --- AES encryption setup ---
key = b'ThisIsASecretKey'    # 16 bytes
iv = b'ThisIsAnInitVect'    # 16 bytes

def encrypt_message(message):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(ciphertext).decode()


# ----------------- ROUTES -----------------

@app.route('/')
def home():
    if "username" in session:
        return render_template('index.html', key=key.decode(), iv=iv.decode())
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user exists
        existing_user = users_collection.find_one({"username": username})
        if existing_user:
            return "Username already exists! Try another."

        # Hash password and save
        hash_pass = generate_password_hash(password)
        users_collection.insert_one({"username": username, "password": hash_pass})

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users_collection.find_one({"username": username})
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return redirect(url_for('home'))  # go to chat
        return "Invalid credentials!"

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


# ----------------- SOCKET.IO -----------------

@socketio.on('message')
def handle_message(msg):
    if "username" not in session:
        return  # ignore if not logged in

    print(f"Received from {session['username']}: {msg}")  

    # Encrypt before sending out
    encrypted = encrypt_message(f"{session['username']}: {msg}")
    send(encrypted, broadcast=True)


# ----------------- MAIN -----------------

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
