from flask import Flask, render_template, request, redirect, session, jsonify, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
import pyotp
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import urllib.parse

import qrcode
import base64
from io import BytesIO




app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messaging.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Setup serializer for password reset tokens
serializer = URLSafeTimedSerializer(app.secret_key)
@app.template_filter('urlencode')
def urlencode_filter(s):
    return urllib.parse.quote_plus(s)
# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # Secure hashed password
    public_key = db.Column(db.Text, nullable=False)
    totp_secret = db.Column(db.String(16), nullable=False)  # Field for TOTP secret

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ciphertext = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Create the database tables if they don't exist
with app.app_context():
    db.create_all()

# Home route: Redirect based on login status
@app.route('/')
def landing():
    if 'username' in session:
        return redirect(url_for('index'))
    return render_template('landing.html')


# Registration: Generate RSA key pair, TOTP secret, and securely hash the password
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash("User already exists. Please choose a different username.", "danger")
            return render_template("register.html")
        
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template("register.html")
        
        # Generate RSA key pair
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Generate TOTP secret and URI
        totp_secret = pyotp.random_base32()
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=username,
            issuer_name="SecureMessagingApp"
        )
        qr_img = qrcode.make(totp_uri)
        buffer = BytesIO()
        qr_img.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
        # Hash password
        password_hash = generate_password_hash(password)
        
        # Save new user
        new_user = User(username=username, password_hash=password_hash,
                        public_key=public_key, totp_secret=totp_secret)
        db.session.add(new_user)
        db.session.commit()
        
        # Show private key and TOTP setup
        return render_template('register_success.html',
                               username=username,
                               private_key=private_key,
                               totp_secret=totp_secret,
                               totp_uri=totp_uri,
                               qr_base64=qr_base64)
    
    return render_template("register.html")


# Login: Validate username and password
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password.", "danger")
            return render_template("login.html")
    return render_template("login.html")

# Logout endpoint
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# Forgot Password: Display form to enter username
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user:
            # Generate a token valid for 30 minutes
            token = serializer.dumps(user.username, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            # For demonstration, we flash the reset link.
            # In production, send this link via email.
            flash(f'Password reset link: {reset_url}', "info")
        else:
            flash("Username not found.", "danger")
        return render_template("forgot_password.html")
    return render_template("forgot_password.html")

# Reset Password: Allow user to enter a new password using the reset token
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        username = serializer.loads(token, salt='password-reset-salt', max_age=1800)
    except SignatureExpired:
        flash("The reset link has expired.", "danger")
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash("Invalid reset link.", "danger")
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", token=token)
        if len(new_password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template("reset_password.html", token=token)
        user = User.query.filter_by(username=username).first()
        if user:
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash("Your password has been updated. Please log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("User not found.", "danger")
            return redirect(url_for('forgot_password'))
    return render_template("reset_password.html", token=token)

# Main messaging interface: Display other users for messaging
@app.route('/index')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    current_user = User.query.filter_by(username=session['username']).first()
    # List all other users for messaging
    users = User.query.filter(User.username != session['username']).all()
    return render_template('index.html', current_user=current_user, users=users)

# Endpoint to send a message (client sends ciphertext)
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    sender = User.query.filter_by(username=session['username']).first()
    recipient_username = request.form['recipient']
    ciphertext = request.form['ciphertext']
    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        return jsonify({'error': 'Recipient not found'}), 404
    msg = Message(sender_id=sender.id, recipient_id=recipient.id, ciphertext=ciphertext)
    db.session.add(msg)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/list_users')
def list_users():
    users = User.query.all()
    usernames = [u.username for u in users]
    return jsonify(usernames)

# Endpoint to retrieve messages for the logged in user
@app.route('/messages')
def messages():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    user = User.query.filter_by(username=session['username']).first()
    received_msgs = Message.query.filter_by(recipient_id=user.id).order_by(Message.timestamp.desc()).all()
    messages_list = []
    for msg in received_msgs:
        sender = User.query.get(msg.sender_id)
        messages_list.append({
            'id': msg.id,
            'sender': sender.username,
            'ciphertext': msg.ciphertext,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })
    return jsonify(messages_list)

# Endpoint to get a user's public key
@app.route('/get_public_key/<username>')
def get_public_key(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({'public_key': user.public_key})
    return jsonify({'error': 'User not found'}), 404

# Endpoint to verify TOTP code for two-factor authentication
@app.route('/verify_totp', methods=['POST'])
def verify_totp():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    totp_code = request.form.get('totp_code')
    user = User.query.filter_by(username=session['username']).first()
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(totp_code):
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Invalid TOTP code'}), 400
    

# Endpoint to delete a received message
@app.route('/delete_message/<int:message_id>', methods=['DELETE'])
def delete_message(message_id):
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    user = User.query.filter_by(username=session['username']).first()
    msg = Message.query.get(message_id)
    if not msg:
        return jsonify({'error': 'Message not found'}), 404
    # Ensure only the recipient can delete the message
    if msg.recipient_id != user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    db.session.delete(msg)
    db.session.commit()
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True)
