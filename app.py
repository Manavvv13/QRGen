from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3, qrcode, os, uuid
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/qrs'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS qr_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            original_url TEXT,
            redirect_id TEXT UNIQUE,
            filename TEXT,
            scan_count INTEGER DEFAULT 0)''')
        conn.commit()

init_db()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        try:
            with get_db_connection() as conn:
                conn.execute('INSERT INTO admins (email, password) VALUES (?, ?)', (email, password))
                conn.commit()
                flash('Registration successful.', 'success')
                return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists.', 'error')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        admin = conn.execute('SELECT * FROM admins WHERE email=?', (email,)).fetchone()
        if admin and check_password_hash(admin['password'], password):
            session['admin_id'] = admin['id']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'error')
        conn.close()
        if admin:
            session['admin_id'] = admin['id']
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('admin_id', None)
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'admin_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    qr_list = conn.execute('SELECT * FROM qr_codes WHERE admin_id = ?', (session['admin_id'],)).fetchall()
    conn.close()
    return render_template('dashboard.html', qr_codes=qr_list)

@app.route('/generate_qrs', methods=['POST'])
def generate_qrs():
    if 'admin_id' not in session:
        return redirect(url_for('login'))

    original_url = request.form.get('url')
    count = int(request.form.get('count'))
    qr_codes = []

    conn = get_db_connection()
    for _ in range(count):
        uid = str(uuid.uuid4())[:8]
        redirect_url = url_for('redirect_to_original', qr_id=uid, _external=True)
        filename = f"{uid}.png"
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        qrcode.make(redirect_url).save(path)

        conn.execute('''INSERT INTO qr_codes (admin_id, original_url, redirect_id, filename)
                        VALUES (?, ?, ?, ?)''', (session['admin_id'], original_url, uid, filename))

        qr_codes.append({'redirect_url': redirect_url, 'filename': filename, 'scan_count': 0})

    conn.commit()
    conn.close()
    return render_template('generate.html', qr_codes=qr_codes)

@app.route('/delete_qr', methods=['POST'])
def delete_qr():
    if 'admin_id' not in session:
        return redirect(url_for('login'))

    qr_id = request.form['qr_id']

    conn = get_db_connection()
    qr = conn.execute('SELECT * FROM qr_codes WHERE id = ? AND admin_id = ?', (qr_id, session['admin_id'])).fetchone()

    if qr:
        # Delete QR image file
        qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr['filename'])
        if os.path.exists(qr_path):
            os.remove(qr_path)

        # Delete record from DB
        conn.execute('DELETE FROM qr_codes WHERE id = ?', (qr_id,))
        conn.commit()

    conn.close()
    flash('QR code deleted successfully.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/r/<qr_id>')
def redirect_to_original(qr_id):
    conn = get_db_connection()
    qr = conn.execute('SELECT * FROM qr_codes WHERE redirect_id=?', (qr_id,)).fetchone()
    if qr:
        conn.execute('UPDATE qr_codes SET scan_count = scan_count + 1 WHERE redirect_id=?', (qr_id,))
        conn.commit()
        conn.close()
        return redirect(qr['original_url'])
    conn.close()
    return 'Invalid QR code.', 404

if __name__ == '__main__':
    app.run(debug=True)
