import os
import json
from flask import Flask, render_template, request, redirect, session, flash, send_file, url_for
from werkzeug.utils import secure_filename
from config import (
    FLASK_SECRET, UPLOAD_FOLDER, ENCRYPTED_FILES_FOLDER, STEGO_FOLDER,
    MASTER_KEY
)
from createdb import init_db, create_database
from crypto.login import hash_password, verify_password
from crypto.db import aes_encrypt, aes_decrypt, execute_query, fetch_query
from crypto.super import super_encrypt, super_decrypt
from crypto.file import encrypt_file, decrypt_file
from crypto.stego import embed_text_in_image, extract_text_from_image
from Crypto.Random import get_random_bytes

# Flask setup
app = Flask(__name__)
app.secret_key = FLASK_SECRET

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FILES_FOLDER, exist_ok=True)
os.makedirs(STEGO_FOLDER, exist_ok=True)

BLOWFISH_KEY = MASTER_KEY[:16]

create_database()
init_db()


@app.route('/')
def index():
    return redirect(url_for('inbox') if 'user' in session else url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash('Username/password required')
            return redirect(url_for('register'))

        exists = fetch_query("SELECT id FROM users WHERE username=%s", (username,), one=True)
        if exists:
            flash('Username already exists.')
            return redirect(url_for('register'))

        execute_query("INSERT INTO users (username, password_hash) VALUES (%s,%s)",
                      (username, hash_password(password)))
        flash('Registration successful.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        row = fetch_query("SELECT password_hash FROM users WHERE username=%s", (username,), one=True)

        if row and verify_password(row['password_hash'], password):
            session['user'] = username
            return redirect(url_for('inbox'))
        else:
            flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/inbox')
def inbox():
    if 'user' not in session:
        return redirect(url_for('login'))
    username = session['user']
    messages = fetch_query("""
        SELECT id, sender, type, created_at FROM messages
        WHERE recipient=%s ORDER BY created_at DESC
    """, (username,))
    return render_template('inbox.html', messages=messages)

@app.route('/sent')
def sent():
    if 'user' not in session:
        return redirect(url_for('login'))
    username = session['user']
    sent_messages = fetch_query("""
        SELECT id, recipient, type, created_at FROM messages
        WHERE sender=%s ORDER BY created_at DESC
    """, (username,))
    return render_template('sent.html', messages=sent_messages)

@app.route('/compose', methods=['GET', 'POST'])
def compose():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        sender = session['user']
        recipient = request.form['recipient'].strip()
        mtype = request.form['mtype']

        if not recipient:
            flash('Recipient required.')
            return redirect(url_for('compose'))

        target = fetch_query("SELECT id FROM users WHERE username=%s", (recipient,), one=True)
        if not target:
            flash(f'User "{recipient}" not found.')
            return redirect(url_for('compose'))

        if mtype == 'text':
            message = request.form['message']
            xor_key = request.form.get('xor_key', 'xorkey')
            enc = aes_encrypt(super_encrypt(message, xor_key))
            execute_query("INSERT INTO messages (sender, recipient, type, payload) VALUES (%s,%s,%s,%s)",
                          (sender, recipient, 'text', enc))

        elif mtype == 'image':
            f = request.files.get('image')
            secret = request.form.get('secret', '')
            if not f:
                flash('No image uploaded')
                return redirect(url_for('compose'))

            filename = secure_filename(f.filename)
            path_in = os.path.join(STEGO_FOLDER, filename)
            f.save(path_in)

            if secret.strip():
                path_out = os.path.join(STEGO_FOLDER, f"stego_{get_random_bytes(6).hex()}_{filename}")
                embed_text_in_image(path_in, path_out, secret)
            else:
                path_out = path_in

            data = json.dumps({'stego_path': path_out}).encode()
            enc = aes_encrypt(data)
            execute_query("INSERT INTO messages (sender, recipient, type, payload) VALUES (%s,%s,%s,%s)",
                          (sender, recipient, 'image', enc))

        elif mtype == 'file':
            f = request.files.get('file')
            if not f:
                flash('No file uploaded.')
                return redirect(url_for('compose'))

            filename = secure_filename(f.filename)
            in_path = os.path.join(UPLOAD_FOLDER, filename)
            f.save(in_path)
            out_path = os.path.join(ENCRYPTED_FILES_FOLDER, f'enc_{get_random_bytes(6).hex()}_{filename}.bin')
            encrypt_file(in_path, out_path, BLOWFISH_KEY)
            data = json.dumps({'file_path': out_path, 'orig_name': filename}).encode()
            enc = aes_encrypt(data)
            execute_query("INSERT INTO messages (sender, recipient, type, payload) VALUES (%s,%s,%s,%s)",
                          (sender, recipient, 'file', enc))

        flash('Message sent.')
        return redirect(url_for('sent'))

    return render_template('compose.html')

@app.route('/view/<int:msg_id>')
def view(msg_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    row = fetch_query("SELECT sender, type, payload FROM messages WHERE id=%s", (msg_id,), one=True)
    if not row:
        flash('Message not found.')
        return redirect(url_for('inbox'))

    sender, mtype, payload = row['sender'], row['type'], row['payload']

    if mtype == 'text':
        cipherbytes = aes_decrypt(payload)
        xor_key = request.args.get('xor_key', 'key')
        try:
            text = super_decrypt(cipherbytes, xor_key)
        except Exception as e:
            text = f"[Error decrypting: {e}]"
        return render_template('view_message.html', sender=sender, content=text, mtype='text')

    elif mtype == 'image':
        obj = json.loads(aes_decrypt(payload).decode())
        path = obj['stego_path']
        try:
            secret = extract_text_from_image(path)
        except Exception as e:
            secret = f"[extract error: {e}]"
        return render_template('view_message.html', sender=sender, mtype='image', image_path='/' + path, content=secret)

    elif mtype == 'file':
        # File tidak langsung dibuka, hanya info + tombol download
        obj = json.loads(aes_decrypt(payload).decode())
        file_name = obj['orig_name']
        return render_template('view_message.html', sender=sender, mtype='file', file_name=file_name, msg_id=msg_id)

    flash('Unsupported type')
    return redirect(url_for('inbox'))

@app.route('/download/<int:msg_id>')
def download_file(msg_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    msg = fetch_query("SELECT payload FROM messages WHERE id=%s", (msg_id,), one=True)
    if not msg:
        flash('File not found')
        return redirect(url_for('inbox'))

    obj = json.loads(aes_decrypt(msg['payload']).decode())
    enc_path = obj['file_path']
    orig_name = obj['orig_name']

    from tempfile import NamedTemporaryFile
    tmp = NamedTemporaryFile(delete=False)
    decrypt_file(enc_path, tmp.name, BLOWFISH_KEY)
    tmp.close()

    return send_file(tmp.name, as_attachment=True, download_name=orig_name)



@app.route('/delete/<string:box>/<int:msg_id>')
def delete(box, msg_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']

    if box == 'inbox':
        execute_query("DELETE FROM messages WHERE id=%s AND recipient=%s", (msg_id, user))
        flash('Message deleted.')
        return redirect(url_for('inbox'))

    elif box == 'sent':
        execute_query("DELETE FROM messages WHERE id=%s AND sender=%s", (msg_id, user))
        flash('Message deleted.')
        return redirect(url_for('sent'))

    else:
        flash('Invalid delete target.')
        return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
