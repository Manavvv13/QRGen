from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode, os, uuid
import datetime
import urllib.parse
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "your_secret_key")
app.config['UPLOAD_FOLDER'] = 'static/qrs'

# PostgreSQL connection string from environment (Render)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Make sure QR folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Admin model
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

# QR Code model
class QRCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    original_url = db.Column(db.Text, nullable=False)
    redirect_id = db.Column(db.String(50), unique=True, nullable=False)
    filename = db.Column(db.String(100), nullable=False)
    scan_count = db.Column(db.Integer, default=0)

    admin = db.relationship('Admin', backref=db.backref('qrs', lazy=True))

# Run only once to initialize DB
@app.route('/init')
def init_db():
    db.create_all()
    return "Database initialized."

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        existing = Admin.query.filter_by(email=email).first()
        if existing:
            flash('Email already exists.', 'error')
        else:
            admin = Admin(email=email, password=password)
            db.session.add(admin)
            db.session.commit()
            flash('Registration successful.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        admin = Admin.query.filter_by(email=email).first()
        if admin and check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('admin_id', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'admin_id' not in session:
        return redirect(url_for('login'))
    qr_list = QRCode.query.filter_by(admin_id=session['admin_id']).all()
    return render_template('dashboard.html', qr_codes=qr_list)

@app.route('/generate_qrs', methods=['POST'])
def generate_qrs():
    if 'admin_id' not in session:
        return redirect(url_for('login'))

    original_url = request.form.get('url')
    count = int(request.form.get('count'))
    qr_codes = []

    for _ in range(count):
        uid = str(uuid.uuid4())[:8]
        redirect_url = url_for('redirect_to_original', qr_id=uid, _external=True)
        filename = f"{uid}.png"
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        qrcode.make(redirect_url).save(path)

        qr = QRCode(
            admin_id=session['admin_id'],
            original_url=original_url,
            redirect_id=uid,
            filename=filename
        )
        db.session.add(qr)
        qr_codes.append({'redirect_url': redirect_url, 'filename': filename, 'scan_count': 0})

    db.session.commit()
    return render_template('generate.html', qr_codes=qr_codes)

@app.route('/delete_qr', methods=['POST'])
def delete_qr():
    if 'admin_id' not in session:
        return redirect(url_for('login'))

    qr_id = request.form['qr_id']
    qr = QRCode.query.filter_by(id=qr_id, admin_id=session['admin_id']).first()

    if qr:
        qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr.filename)
        if os.path.exists(qr_path):
            os.remove(qr_path)

        db.session.delete(qr)
        db.session.commit()
        flash('QR code deleted successfully.', 'success')

    return redirect(url_for('dashboard'))

@app.route('/init')
def init():
    db.create_all()
    return "Tables created."

@app.route('/r/<qr_id>')
def redirect_to_original(qr_id):
    qr = QRCode.query.filter_by(redirect_id=qr_id).first()
    if qr:
        qr.scan_count += 1
        db.session.commit()
        return redirect(qr.original_url)
    return 'Invalid QR code.', 404

if __name__ == '__main__':
    app.run(debug=True)
