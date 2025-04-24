# Secure Two-User Messaging System

A lightweight web application demonstrating secure two-way messaging between users using RSA encryption and TOTP-based two-factor authentication (2FA). Built with Python, Flask, and SQLAlchemy on the backend, and Bootstrap + JSEncrypt on the frontend.

---

## Features

- **User Registration & Authentication**
  - Secure password storage with salted hashing (`werkzeug.security`).
  - RSA key pair generation for each user; public keys stored server-side, private keys held by users.
  - TOTP (Time-based One-Time Password) secret generation for 2FA via `pyotp`.
- **Messaging Workflow**
  - Exchange public keys between users.
  - Client-side encryption using the recipient’s public key (JSEncrypt).
  - Messages stored in encrypted form in a SQLite database.
  - Client-side decryption requiring both the private key and a current TOTP code.
- **Password Reset**
  - Token-based password reset flow using `itsdangerous` with 30-minute expiration.
- **Message Management**
  - View and refresh received messages in real time.
  - Delete messages you have received.
- **Usability**
  - Hide/Show toggle for the private key textarea.
  - Responsive UI built with Bootstrap.

---

## Requirements

- Python 3.7+
- Virtual environment (recommended)
- Git (for cloning)

**Python Packages**:

```text
Flask
flask_sqlalchemy
cryptography
pyotp
werkzeug
itsdangerous
```

---

## Installation

1. **Clone the repository**
```
git clone https://github.com/daredevilx616/RSA-ChatApp.git
cd RSA-ChatApp
```

2. **Install dependencies**
```
pip install -r requirements.txt
```

3. **Initialize the database**
```
python
>>> from app import db
>>> db.create_all()
>>> exit()
```

4. **Run the application**
```
export FLASK_APP=app.py        # macOS/Linux
set FLASK_APP=app.py           # Windows
flask run
```

Open your browser at `http://127.0.0.1:5000`.

---

## Configuration

- **Flask Secret Key**
  - In `app.py`, set `app.secret_key` to a secure, random string in production.
- **Environment Variables** (optional)
  - You can load `GITHUB_TOKEN`, or any other API tokens, from environment variables instead of hard-coding them.

---

## Usage

1. **Register** a new account. Save your private key and TOTP secret securely.
2. **Log in** with your username and password.
3. **Send a message**: enter the recipient’s username and your plaintext message. It will be encrypted client-side and stored.
4. **Receive messages**: click **Refresh Messages**. For each message, enter the current TOTP code and click **Decrypt**—your private key + TOTP code unlocks the message.
5. **Delete** messages you no longer need by clicking **Delete** under each entry.
6. **Reset Password**: if you forget your password, click **Forgot Password?**, enter your username, then follow the reset link.

---

## File Structure

```text
├── app.py                # Main Flask application
├── requirements.txt      # Python dependencies
├── messaging.db          # SQLite database (auto-created)
├── templates/            # Jinja2 HTML templates
│   ├── base.html
│   ├── landing.html
│   ├── register.html
│   ├── register_success.html
│   ├── login.html
│   ├── forgot_password.html
│   ├── reset_password.html
│   └── index.html
└── static/
    └── background.jpg    # Background image for UI
```

---

## Security Considerations

- **Private Key Protection**: The private key is never sent to the server and is only stored in the user’s browser.
- **2FA**: TOTP code required for decryption ensures that even if a private key leaks, messages remain safe without the current OTP.
- **Password Hashing**: Passwords are stored as salted hashes—never plaintext.
- **Secret Management**: Do not commit API tokens or secrets; use environment variables.

---

## Future Improvements

- Add recipient search/autocomplete.
- Mobile-responsive enhancements.
- Real-time WebSocket-based messaging.
- Advanced logging and error handling.
- Support for larger user base and production-grade database.

---

## Contributing

1. Fork the repo.
2. Create a feature branch: `git checkout -b feature-name`.
3. Commit your changes: `git commit -m "Add some feature"`.
4. Push to branch: `git push origin feature-name`.
5. Open a Pull Request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

