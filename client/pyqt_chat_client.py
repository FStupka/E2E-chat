"""
pyqt_chat_client.py

PyQt6 GUI client for the updated E2E-chat backend.

Server changes handled here:
- /register expects CSR (not public_key).
- /users lists all users except current.
- /messages/send sends ciphertext + per-user encrypted keys (list).
- /messages/{user_id} fetches messages in the conversation with that target user.
- Certificates are used as "public key container" (public_key_cert).

not really, one keystorage is enough
Local demo: run TWO instances with different key storage folders:
  set PRIVATEKEY_STORAGE=key_storage_alice
  python pyqt_chat_client.py

  set PRIVATEKEY_STORAGE=key_storage_bob
  python pyqt_chat_client.py
"""

from __future__ import annotations
import base64, json, os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import requests
from dotenv import load_dotenv
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QSize, pyqtSignal, QPoint
from PyQt6.QtGui import QFont, QIcon, QPalette, QColor, QPainter, QLinearGradient, QAction
from PyQt6.QtWidgets import *

#
# ==# ---------------------------------------------------------------------------
# # Environment / paths
# # ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

SERVER_ADDRESS = os.getenv("SERVER_ADDRESS", "localhost")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8088"))

# Your server is HTTPS with a self-signed cert.
# This file must be the transport certificate (the one used by uvicorn SSL).
SERVER_CERTIFICATE_PATH = os.getenv("SERVER_TRANSPORT_CERTIFICATE_PATH", "../server/certs/transport_cert.pem")

PRIVATEKEY_STORAGE = os.getenv("PRIVATEKEY_STORAGE", "key_storage")
PRIVATEKEY_STORAGE_PATH = (BASE_DIR / PRIVATEKEY_STORAGE).resolve()
PRIVATEKEY_STORAGE_PATH.mkdir(parents=True, exist_ok=True)

SERVER_URL = f"https://{SERVER_ADDRESS}:{SERVER_PORT}"
SERVER_STORAGE_CERTIFICATE_PATH = str((BASE_DIR / os.getenv("SERVER_STORAGE_CERTIFICATE_PATH", "../server/certs/storage_cert.pem")).resolve())

def load_storage_ca_cert() -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(SERVER_STORAGE_CERTIFICATE_PATH).read_bytes())
STORAGE_CA_CERT = load_storage_ca_cert()

# === THEME SYSTEM ===
class AppTheme:
    LIGHT = {
        'bg': '#F5F7FA', 'card': '#FFFFFF', 'input': '#FFFFFF', 'bubble_me': '#007AFF', 'bubble_them': '#E9ECEF',
        'text': '#1A1A1A', 'text_secondary': '#6B7280', 'text_on_primary': '#FFFFFF', 'border': '#E5E7EB',
        'accent': '#007AFF', 'accent_hover': '#0051D5', 'danger': '#DC3545', 'success': '#28A745', 'bg_chosen': '#BEBEBE'
    }
    DARK = {
        'bg': '#1A1D21', 'card': '#242832', 'input': '#2D323E', 'bubble_me': '#0A84FF', 'bubble_them': '#2D323E',
        'text': '#E8EAED', 'text_secondary': '#9BA1A6', 'text_on_primary': '#FFFFFF', 'border': '#3E4451',
        'accent': '#0A84FF', 'accent_hover': '#409CFF', 'danger': '#FF453A', 'success': '#30D158', 'bg_chosen': '#545454'
    }

def get_stylesheet(dark_mode: bool) -> str:
    t = AppTheme.DARK if dark_mode else AppTheme.LIGHT
    return f"""
QWidget {{ background: {t['bg']}; color: {t['text']}; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 14px; }}
QPushButton {{ 
    background: {t['accent']}; 
    color: {t['text_on_primary']}; 
    border: none; 
    border-radius: 8px; 
    padding: 10px 20px; 
    font-weight: 600;
    font-size: 14px;
}}
QPushButton:hover {{ background: {t['accent_hover']}; }}
QPushButton:disabled {{ background: {t['border']}; color: {t['text_secondary']}; }}
QPushButton#secondary {{ 
    background: {t['card']}; 
    color: {t['text']}; 
    border: 2px solid {t['border']};
    font-size: 14px;
}}
QPushButton#secondary:hover {{ background: {t['border']}; }}
QPushButton#danger {{ 
    background: {t['danger']};
    color: {t['text_on_primary']};
    font-size: 14px;
}}
QLineEdit, QTextEdit, QComboBox {{ background: {t['input']}; color: {t['text']}; border: 2px solid {t['border']}; border-radius: 8px; padding: 12px; }}
QLineEdit:focus, QTextEdit:focus, QComboBox:focus {{ border-color: {t['accent']}; }}
QLabel#title {{ font-size: 28px; font-weight: 700; }}
QLabel#subtitle {{ color: {t['text_secondary']}; font-size: 13px; }}
QFrame#card {{ background: {t['card']}; border-radius: 0px; }}
QFrame#separator {{ background: {t['border']}; }}
QFrame#userItem:hover {{ background: {t['border']}; }}
QScrollBar:vertical {{ background: {t['bg']}; width: 10px; border-radius: 5px; }}
QScrollBar::handle:vertical {{ background: {t['border']}; border-radius: 5px; }}
QScrollBar::handle:vertical:hover {{ background: {t['text_secondary']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
"""

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def b64e_url(data: bytes) -> str:
    """urlsafe base64 (matches your server usage for ciphertext + keys)."""
    return base64.urlsafe_b64encode(data).decode("utf-8")


def b64d_url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("utf-8"))


def info(parent: QWidget, title: str, text: str) -> None:
    QMessageBox.information(parent, title, text)


def warn(parent: QWidget, title: str, text: str) -> None:
    QMessageBox.warning(parent, title, text)


def err(parent: QWidget, title: str, text: str) -> None:
    QMessageBox.critical(parent, title, text)


# ---------------------------------------------------------------------------
# HTTP client wrapper for your NEW backend
# ---------------------------------------------------------------------------

@dataclass
class AuthContext:
    username: str
    user_id: str
    private_key: RSAPrivateKey
    api_key: str


class ApiClient:
    def __init__(self, server_url: str, verify_path: str | Path):
        self.server_url = server_url.rstrip("/")

        # requests verify expects a path to the server cert (for self-signed)
        verify_path = Path(verify_path)
        self.verify_path = str((BASE_DIR / verify_path).resolve()) if not verify_path.is_absolute() else str(verify_path)

    # --------------------
    # AUTH / REGISTER
    # --------------------
    def register_user(self, username: str, csr_pem: str) -> None:
        """
        POST /register
        body: {"username": "...", "csr": "-----BEGIN CERTIFICATE REQUEST-----..."}
        """
        payload = {"username": username, "csr": csr_pem}
        r = requests.post(f"{self.server_url}/register", json=payload, verify=self.verify_path)

        # 200 OK = new user
        # 409 CONFLICT = user exists -> fine for local demo
        if r.status_code in (200, 409):
            return
        raise RuntimeError(f"Register failed: {r.status_code} {r.text}")

    def get_api_key_encrypted(self, username: str) -> str:
        """
        POST /get_api
        returns {"api_key": "<urlsafe b64 RSA-encrypted api key>"}
        """
        r = requests.post(f"{self.server_url}/get_api", json={"username": username}, verify=self.verify_path)
        if r.status_code != 200:
            raise RuntimeError(f"get_api failed: {r.status_code} {r.text}")
        return r.json()["api_key"]

    def authenticate(self, username: str, api_key: str, signature_b64: str, timestamp_iso: str) -> dict:
        """
        POST /authenticate
        body: {username, api_key, timestamp, signature}
        returns {"status":"authenticated","user_id":"..."}
        """
        payload = {
            "username": username,
            "api_key": api_key,
            "timestamp": timestamp_iso,
            "signature": signature_b64,
        }
        r = requests.post(f"{self.server_url}/authenticate", json=payload, verify=self.verify_path)
        if r.status_code != 200:
            raise RuntimeError(f"authenticate failed: {r.status_code} {r.text}")
        return r.json()

    def logout(self, api_key: str) -> None:
        r = requests.post(f"{self.server_url}/logout", headers={"x-api-key": api_key}, verify=self.verify_path)
        if r.status_code != 200:
            raise RuntimeError(f"logout failed: {r.status_code} {r.text}")

    # --------------------
    # USERS
    # --------------------
    def list_users(self, api_key: str) -> list[dict]:
        """
        GET /users
        returns list of {"id": "...", "username": "..."} excluding current user.
        """
        r = requests.get(f"{self.server_url}/users", headers={"x-api-key": api_key}, verify=self.verify_path)
        if r.status_code != 200:
            raise RuntimeError(f"/users failed: {r.status_code} {r.text}")
        return r.json()

    def get_user_cert(self, api_key: str, user_id: str) -> x509.Certificate:
        """
        Server route should be: /users/{user_id}
        """
        path = f"/users/{user_id}"
        r = requests.get(
            f"{self.server_url}{path}",
            headers={"x-api-key": api_key},
            verify=self.verify_path,
        )

        if r.status_code == 200:
            pem = r.json()["public_key_cert"].encode("utf-8")
            return x509.load_pem_x509_certificate(pem)

        raise RuntimeError(f"Cannot fetch user cert for {user_id}.")

    # --------------------
    # MESSAGES
    # --------------------
    def send_message(
        self,
        api_key: str,
        recipient_id: str,
        ciphertext_blob: bytes,
        keys: list[dict],
        timestamp_iso: str,
    ) -> None:
        """
        POST /messages/send
        body:
          {
            "ciphertext": "<urlsafe b64>",
            "keys": [{"encryption_key":"<urlsafe b64>", "user_id":"..."}],
            "recipient_id": "...",
            "timestamp": "<iso>"
          }
        """
        payload = {
            "ciphertext": b64e_url(ciphertext_blob),
            "keys": keys,
            "recipient_id": recipient_id,
            "timestamp": timestamp_iso,
        }
        r = requests.post(
            f"{self.server_url}/messages/send",
            json=payload,
            headers={"x-api-key": api_key},
            verify=self.verify_path,
        )
        if r.status_code != 200:
            raise RuntimeError(f"send failed: {r.status_code} {r.text}")

    def receive_messages(self, api_key: str, target_user_id: str) -> list[dict]:
        """
        GET /messages/{user_id}
        returns list of:
          {
            "message_id": "...",
            "sender_username": "...",
            "ciphertext": "<urlsafe b64>",
            "enc_key": "<urlsafe b64>",
            "timestamp": "<iso>"
          }
        """
        r = requests.get(
            f"{self.server_url}/messages/{target_user_id}",
            headers={"x-api-key": api_key},
            verify=self.verify_path,
        )
        if r.status_code != 200:
            raise RuntimeError(f"receive failed: {r.status_code} {r.text}")
        return r.json()


# ---------------------------------------------------------------------------
# Crypto primitives for the GUI
# ---------------------------------------------------------------------------

def private_key_path(username: str) -> Path:
    return PRIVATEKEY_STORAGE_PATH / f"{username}_private.pem"


def ensure_rsa_keypair(username: str, password: str) -> tuple[RSAPrivateKey, bool]:
    """
    Generates (or loads) local RSA private key.
    Key is encrypted locally with `password`.
    """
    p = private_key_path(username)
    if p.exists():
        return load_private_key(username, password), False

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    p.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
    )
    return private_key, True


def load_private_key(username: str, password: str) -> RSAPrivateKey:
    data = private_key_path(username).read_bytes()
    return serialization.load_pem_private_key(data, password=password.encode("utf-8"))  # type: ignore[return-value]


def build_csr(username: str, private_key: RSAPrivateKey) -> str:
    """
    Build CSR with CN=username (server enforces this).
    """
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, username)])
        )
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def decrypt_api_key(private_key: RSAPrivateKey, encrypted_api_key_b64_urlsafe: str) -> str:
    encrypted = b64d_url(encrypted_api_key_b64_urlsafe)
    api_key_bytes = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return api_key_bytes.decode("utf-8")


def sign_api_key(private_key: RSAPrivateKey, timestamp_iso: str, api_key: str) -> str:
    """
    Server verifies signature over: f"{timestamp} - {api_key}"
    """
    data_to_sign = f"{timestamp_iso} - {api_key}".encode("utf-8")
    signature = private_key.sign(
        data_to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return b64e_url(signature)


def validate_user_cert(cert: x509.Certificate, expected_username: str, ca_cert: x509.Certificate) -> bool:
    try:
        # issuer check
        if cert.issuer != ca_cert.subject:
            return False

        # CN check
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        if cn != expected_username:
            return False

        # time validity
        now = datetime.now(timezone.utc)
        if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
            return False

        # signature verification (storage CA signs user certs)
        ca_pub = ca_cert.public_key()
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,  # typically SHA256
        )
        return True

    except Exception:
        return False



def canonical_payload_bytes(payload: dict) -> bytes:
    # stable bytes so signature verifies across machines
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_payload(priv: RSAPrivateKey, payload: dict) -> str:
    data = canonical_payload_bytes(payload)
    sig = priv.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return b64e_url(sig)


def verify_payload_signature(pub: RSAPublicKey, payload: dict, sig_b64: str) -> bool:
    try:
        sig = b64d_url(sig_b64)
        data = canonical_payload_bytes(payload)
        pub.verify(
            sig,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

#chat encryption

def encrypt_chat_payload(sender: str, recipient: str, text: str, sender_priv: RSAPrivateKey) -> tuple[bytes, bytes]:
    payload = {
        "sender": sender,
        "recipient": recipient,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "text": text,
    }

    # IMPORTANT: sign payload WITHOUT signature field
    sig = sign_payload(sender_priv, payload)
    payload["signature"] = sig

    plaintext = canonical_payload_bytes(payload)

    aes_key = os.urandom(32)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return nonce + ciphertext, aes_key


def decrypt_chat_payload(ciphertext_blob: bytes, aes_key: bytes) -> dict:
    nonce = ciphertext_blob[:16]
    ciphertext = ciphertext_blob[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return json.loads(plaintext.decode("utf-8"))


def rsa_encrypt_key(pub: RSAPublicKey, aes_key: bytes) -> bytes:
    return pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt_key(priv: RSAPrivateKey, enc_key: bytes) -> bytes:
    return priv.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

# === UI COMPONENTS ===
class ThemeToggle(QPushButton):
    toggled = pyqtSignal(bool)

    def __init__(self, dark_mode: bool):
        super().__init__()
        self.dark_mode = dark_mode
        self.setFixedSize(60, 40)
        self.setCheckable(True)
        self.setChecked(dark_mode)
        self.clicked.connect(lambda: self.toggled.emit(self.isChecked()))
        self.update_style()

    def update_style(self):
        self.setText("🌙" if self.dark_mode else "☀️")
        self.setStyleSheet(f"""
            QPushButton {{ background: {'#2D323E' if self.dark_mode else '#E5E7EB'}; border-radius: 16px; 
                          font-size: 16px; padding: 0; }}
            QPushButton:hover {{ background: {'#3E4451' if self.dark_mode else '#D1D5DB'}; }}
        """)

    def set_dark_mode(self, dark: bool):
        self.dark_mode = dark
        self.update_style()

class ExitButton(QPushButton):
    def __init__(self):
        super().__init__("⏻")
        self.setFixedSize(60, 40)
        self.setToolTip("Exit")
        self.setStyleSheet("""
            QPushButton {
                background: #DC3545;
                color: white;
                border-radius: 16px;
                font-size: 16px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #B02A37;
            }
        """)

class LoginScreen(QWidget):
    def __init__(self, api: ApiClient, on_logged_in, dark_mode: bool):
        super().__init__()
        self.api = api
        self.on_logged_in = on_logged_in

        layout = QVBoxLayout()
        layout.setContentsMargins(80, 60, 80, 60)
        layout.setSpacing(24)
        self.setLayout(layout)

        # Title
        title = QLabel("🔐 E2E Chat")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("End-to-end encrypted messaging")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)
        layout.addSpacing(20)

        # Form
        self.username = QLineEdit()
        self.username.setPlaceholderText("Username")
        self.username.setMaxLength(32)
        self.password = QLineEdit()
        self.password.setPlaceholderText("Password (min 10 chars)")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)

        layout.addWidget(self.username)
        layout.addWidget(self.password)

        self.status = QLabel("")
        self.status.setObjectName("subtitle")
        self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        # Buttons
        btn_layout = QHBoxLayout()
        self.reg_btn = QPushButton("Register")
        self.reg_btn.setObjectName("secondary")
        self.reg_btn.clicked.connect(self._register)
        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self._login)
        btn_layout.addWidget(self.reg_btn)
        btn_layout.addWidget(self.login_btn)
        layout.addLayout(btn_layout)

        footer = QLabel(f"🌐 {SERVER_URL}\n")
        footer.setObjectName("subtitle")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(footer)
        layout.addStretch()

    def _set_busy(self, busy: bool, msg: str = ""):
        self.username.setEnabled(not busy)
        self.password.setEnabled(not busy)
        self.reg_btn.setEnabled(not busy)
        self.login_btn.setEnabled(not busy)
        self.status.setText(msg)

    def _register(self):
        username, password = self.username.text().strip(), self.password.text()
        if not username or not username.isalnum() or len(username) > 32:
            return warn(self, "Invalid", "Username must be alphanumeric, max 32 chars")
        if len(password) < 10:
            return warn(self, "Invalid", "Password must be at least 10 characters")

        try:
            self._set_busy(True, "Generating keypair...")
            priv, is_new = ensure_rsa_keypair(username, password)
            self._set_busy(True, "Building CSR and registering...")
            csr_pem = build_csr(username, priv)
            self.api.register_user(username, csr_pem)
            # Helpful UX messaging
            if is_new:
                self._set_busy(False, "✓ Registered. You can now click Login.")
                info(self, "Registered", "✓ Registration completed. Now click Login.")
            else:
                self._set_busy(False, "Registration checked. You can now click Login.")
                info(self, "Register", "User already had a local key. Registration checked/updated. Now click Login.")

        except Exception as e:
            self._set_busy(False, "")
            err(self, "Register failed", str(e))

    def _login(self):
        username, password = self.username.text().strip(), self.password.text()
        if not private_key_path(username).exists():
            return warn(self, "Not Found", "No key found. Register first.")
        if not username or not password or len(password) < 10:
            return warn(self, "Invalid", "Check username and password")

        try:
            self._set_busy(True, "Generating/loading local keypair...")
            priv, is_new = ensure_rsa_keypair(username, password)

            if is_new:
                self._set_busy(True, "Building CSR and registering...")
                csr_pem = build_csr(username, priv)
                self.api.register_user(username, csr_pem)

            self._set_busy(True, "Requesting API key...")
            encrypted_api = self.api.get_api_key_encrypted(username)
            api_key = decrypt_api_key(priv, encrypted_api)

            self._set_busy(True, "Authenticating...")
            ts = datetime.now(timezone.utc).isoformat()
            sig = sign_api_key(priv, ts, api_key)
            auth_resp = self.api.authenticate(username, api_key, sig, ts)

            user_id = str(auth_resp["user_id"])
            self._set_busy(False, "Logged in.")
            self.on_logged_in(AuthContext(username=username, user_id=user_id, private_key=priv, api_key=api_key))

        except Exception as e:
            self._set_busy(False, "")
            err(self, "Login failed", str(e))

class ChatBubble(QFrame):
    def __init__(self, sender: str, ts: str, text: str, is_me: bool, dark: bool):
        super().__init__()
        self.setObjectName("card")
        t = AppTheme.DARK if dark else AppTheme.LIGHT
        bg = t['bubble_me'] if is_me else t['bubble_them']
        tc = t['text_on_primary'] if is_me else t['text']

        self.setStyleSheet(f"""
            QFrame#card {{ background: {bg}; border-radius: 12px; padding: 10px 14px; }}
            QLabel {{ color: {tc}; background: transparent; }}
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        self.setLayout(layout)

        header = QHBoxLayout()
        name = QLabel(f"<b>{sender}</b>")
        time = QLabel(ts)
        time.setStyleSheet("font-size: 11px; opacity: 0.7;")
        header.addWidget(name)
        header.addWidget(time)
        header.addStretch()
        layout.addLayout(header)

        msg = QLabel(text)
        msg.setWordWrap(True)
        layout.addWidget(msg)

        if is_me:
            self.setMaximumWidth(400)
            self.setContentsMargins(50, 4, 8, 4)
        else:
            self.setMaximumWidth(400)
            self.setContentsMargins(8, 4, 50, 4)

class UserListItem(QFrame):
    clicked = pyqtSignal(str, str)  # user_id, username

    def __init__(self, user_id: str, username: str, dark_mode: bool):
        super().__init__()
        self.user_id = user_id
        self.username = username
        self.dark_mode = dark_mode
        self.selected = False

        self.setObjectName("userItem")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(60)

        layout = QHBoxLayout()
        layout.setContentsMargins(16, 10, 16, 10)
        self.setLayout(layout)

        # Avatar circle
        avatar = QLabel(username[0].upper())
        avatar.setFixedSize(40, 40)
        avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        avatar.setStyleSheet(f"""
            background: {'#0A84FF' if dark_mode else '#007AFF'};
            color: white;
            border-radius: 20px;
            font-weight: 700;
            font-size: 16px;
        """)
        layout.addWidget(avatar)

        # Username
        name_label = QLabel(username)
        name_label.setStyleSheet("font-weight: 600; font-size: 14px; background:transparent;")
        layout.addWidget(name_label)
        layout.addStretch()

        # Online indicator
        # indicator = QLabel("●")
        # indicator.setStyleSheet("color: #30D158; font-size: 12px; background:transparent;")
        # layout.addWidget(indicator)

        self.update_style()

    def update_style(self):
        t = AppTheme.DARK if self.dark_mode else AppTheme.LIGHT
        if self.selected:
            self.setStyleSheet(f"QFrame#userItem {{ background: {t['bg_chosen']}; border-radius: 8px; }}")
        else:
            self.setStyleSheet(f"QFrame#userItem {{ background: transparent; border-radius: 8px; }}")

    def set_selected(self, selected: bool):
        self.selected = selected
        self.update_style()

    def mousePressEvent(self, event):
        self.clicked.emit(self.user_id, self.username)

class ChatScreen(QWidget):
    def __init__(self, api: ApiClient, on_logout, dark_mode: bool):
        super().__init__()
        self.api = api
        self.on_logout = on_logout
        self.dark_mode = dark_mode
        self.auth = None
        self.target_id = None
        self.target_name = None
        self.target_pub = None
        self.seen = set()
        self.user_items = []

        # Main horizontal layout (sidebar + chat)
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        self.setLayout(main_layout)

        # === LEFT SIDEBAR ===
        sidebar = QFrame()
        sidebar.setObjectName("card")
        sidebar.setFixedWidth(280)
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)
        sidebar.setLayout(sidebar_layout)

        # Sidebar header
        sidebar_header = QFrame()
        sidebar_header.setFixedHeight(70)
        header_layout = QVBoxLayout()
        header_layout.setContentsMargins(16, 12, 16, 12)
        sidebar_header.setLayout(header_layout)

        self.user_label = QLabel("Not logged in")
        self.user_label.setStyleSheet("font-weight: 700; font-size: 16px;")
        header_layout.addWidget(self.user_label)

        messages_label = QLabel("Messages")
        messages_label.setObjectName("subtitle")
        header_layout.addWidget(messages_label)

        sidebar_layout.addWidget(sidebar_header)

        # Separator
        sep1 = QFrame()
        sep1.setObjectName("separator")
        sep1.setFixedHeight(1)
        sidebar_layout.addWidget(sep1)

        # User list scroll area
        self.user_scroll = QScrollArea()
        self.user_scroll.setWidgetResizable(True)
        self.user_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self.user_list_widget = QWidget()
        self.user_list_layout = QVBoxLayout()
        self.user_list_layout.setContentsMargins(8, 8, 8, 8)
        self.user_list_layout.setSpacing(4)
        self.user_list_layout.addStretch()
        self.user_list_widget.setLayout(self.user_list_layout)
        self.user_scroll.setWidget(self.user_list_widget)

        sidebar_layout.addWidget(self.user_scroll, 1)

        # Separator
        sep2 = QFrame()
        sep2.setObjectName("separator")
        sep2.setFixedHeight(1)
        sidebar_layout.addWidget(sep2)

        # Sidebar footer buttons
        sidebar_footer = QFrame()
        sidebar_footer.setFixedHeight(100)
        footer_layout = QVBoxLayout()
        footer_layout.setContentsMargins(12, 10, 12, 10)
        footer_layout.setSpacing(8)
        sidebar_footer.setLayout(footer_layout)

        self.refresh_btn = QPushButton("🔄 Refresh Users")
        self.refresh_btn.setObjectName("secondary")
        self.refresh_btn.setMinimumHeight(36)
        self.refresh_btn.clicked.connect(self._refresh_users)
        footer_layout.addWidget(self.refresh_btn)

        self.logout_btn = QPushButton("Logout")
        self.logout_btn.setObjectName("danger")
        self.logout_btn.setMinimumHeight(36)
        self.logout_btn.clicked.connect(self._logout)
        footer_layout.addWidget(self.logout_btn)

        sidebar_layout.addWidget(sidebar_footer)

        main_layout.addWidget(sidebar)

        # === RIGHT CHAT AREA ===
        chat_container = QWidget()
        chat_layout = QVBoxLayout()
        chat_layout.setContentsMargins(0, 0, 0, 0)
        chat_layout.setSpacing(0)
        chat_container.setLayout(chat_layout)

        # Chat header
        chat_header = QFrame()
        chat_header.setObjectName("card")
        chat_header.setFixedHeight(70)
        chat_header_layout = QHBoxLayout()
        chat_header_layout.setContentsMargins(20, 10, 20, 10)
        chat_header.setLayout(chat_header_layout)

        self.chat_title = QLabel("Select a user to start chatting")
        self.chat_title.setStyleSheet("font-weight: 700; font-size: 16px; background:transparent;")
        chat_header_layout.addWidget(self.chat_title)
        chat_header_layout.addStretch()

        chat_layout.addWidget(chat_header)

        # Chat messages area
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self.chat_widget = QWidget()
        self.chat_layout = QVBoxLayout()
        self.chat_layout.setSpacing(8)
        self.chat_layout.setContentsMargins(20, 20, 20, 20)
        self.chat_layout.addStretch()
        self.chat_widget.setLayout(self.chat_layout)
        self.scroll.setWidget(self.chat_widget)

        chat_layout.addWidget(self.scroll, 1)

        # Input area
        input_frame = QFrame()
        input_frame.setObjectName("card")
        input_frame.setFixedHeight(100)
        input_layout = QHBoxLayout()
        input_layout.setContentsMargins(20, 15, 20, 15)
        input_frame.setLayout(input_layout)

        self.msg_input = QTextEdit()
        self.msg_input.setPlaceholderText("Type a message...")
        self.msg_input.setMaximumHeight(70)
        input_layout.addWidget(self.msg_input, 1)

        self.send_btn = QPushButton("Send")
        self.send_btn.setFixedSize(80, 70)
        self.send_btn.clicked.connect(self._send)
        input_layout.addWidget(self.send_btn)

        chat_layout.addWidget(input_frame)

        main_layout.addWidget(chat_container, 1)

        self.timer = QTimer()
        self.timer.timeout.connect(self._poll)
        self.timer.setInterval(1000)

        self._set_enabled(False)

    def start(self, auth: AuthContext):
        self.auth = auth
        self.user_label.setText(f"👤 {auth.username}")
        self.seen.clear()
        self.target_id = None
        self.target_name = None
        self.target_pub = None
        self._clear_chat()
        self._set_enabled(True)
        self.timer.start()
        self._refresh_users()

    def stop(self):
        self.timer.stop()
        self.auth = None
        self._set_enabled(False)
        self._clear_chat()
        self._clear_user_list()

    def _set_enabled(self, en: bool):
        self.refresh_btn.setEnabled(en)
        self.msg_input.setEnabled(en)
        self.send_btn.setEnabled(en)
        self.logout_btn.setEnabled(en)

    def _logout(self):
        if self.auth:
            try: self.api.logout(self.auth.api_key)
            except: pass
            self.stop()
            self.on_logout()

    def _clear_user_list(self):
        while self.user_list_layout.count() > 1:
            item = self.user_list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.user_items.clear()

    def _refresh_users(self):
        if not self.auth: return
        try:
            users = self.api.list_users(self.auth.api_key)
            self._clear_user_list()

            if not users:
                empty_label = QLabel("No other users online")
                empty_label.setObjectName("subtitle")
                empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                empty_label.setStyleSheet("padding: 20px;")
                self.user_list_layout.insertWidget(0, empty_label)
            else:
                for u in users:
                    item = UserListItem(u["id"], u["username"], self.dark_mode)
                    item.clicked.connect(self._select_user)
                    self.user_list_layout.insertWidget(self.user_list_layout.count() - 1, item)
                    self.user_items.append(item)
        except Exception as e:
            if "401" in str(e):
                err(self, "Session Expired", "Please login again")
                self.stop()
                self.on_logout()

    def _select_user(self, uid: str, uname: str):
        if not self.auth: return

        try:
            cert = self.api.get_user_cert(self.auth.api_key, uid)
            if not validate_user_cert(cert, uname, STORAGE_CA_CERT):
                raise RuntimeError("Invalid certificate")

            self.target_id = uid
            self.target_name = uname
            self.target_pub = cert.public_key()
            self.chat_title.setText(f"💬 {uname}")

            # Update selection in sidebar
            for item in self.user_items:
                item.set_selected(item.user_id == uid)

            self._clear_chat()
            self.seen.clear()
            self._add_system(f"Chat with {uname}")

            # Load history
            msgs = self.api.receive_messages(self.auth.api_key, self.target_id)
            for m in msgs:
                mid = m.get("message_id", "")
                if not mid or mid in self.seen: continue
                try:
                    ct = b64d_url(m["ciphertext"])
                    ek = b64d_url(m["enc_key"])
                    aes = rsa_decrypt_key(self.auth.private_key, ek)
                    p = decrypt_chat_payload(ct, aes)

                    sender = m.get("sender_username", "?")
                    text = p.get("text", "")
                    ts = self._fmt_ts(m.get("timestamp", ""))

                    self.seen.add(mid)

                    # Verify signature if from target
                    sig = p.get("signature")
                    if sig and self.target_pub and sender == self.target_name:
                        pv = dict(p)
                        pv.pop("signature", None)
                        if not verify_payload_signature(self.target_pub, pv, sig):
                            text = "[⚠️ INVALID SIG] " + text

                    self._add_bubble(sender, ts, text, sender == self.auth.username)
                except: continue
        except Exception as e:
            err(self, "Error", str(e))

    def _send(self):
        if not self.auth or not self.target_id or not self.target_pub: return
        text = self.msg_input.toPlainText().strip()
        if not text: return
        self.msg_input.clear()

        try:
            ct, aes = encrypt_chat_payload(self.auth.username, self.target_name, text, self.auth.private_key)

            ek_me = rsa_encrypt_key(self.auth.private_key.public_key(), aes)
            ek_them = rsa_encrypt_key(self.target_pub, aes)

            keys = [
                {"encryption_key": b64e_url(ek_me), "user_id": self.auth.user_id},
                {"encryption_key": b64e_url(ek_them), "user_id": self.target_id}
            ]

            ts = datetime.now(timezone.utc).isoformat()
            self.api.send_message(self.auth.api_key, self.target_id, ct, keys, ts)

            self._add_bubble(self.auth.username, self._fmt_ts(ts), text, True)
        except Exception as e:
            err(self, "Send Failed", str(e))

    def _poll(self):
        if not self.auth or not self.target_id: return
        try:
            msgs = self.api.receive_messages(self.auth.api_key, self.target_id)
        except: return

        for m in msgs:
            mid = m.get("message_id", "")
            if not mid or mid in self.seen: continue
            try:
                ct = b64d_url(m["ciphertext"])
                ek = b64d_url(m["enc_key"])
                aes = rsa_decrypt_key(self.auth.private_key, ek)
                p = decrypt_chat_payload(ct, aes)

                sender = m.get("sender_username", "?")
                text = p.get("text", "")
                ts = self._fmt_ts(m.get("timestamp", ""))

                self.seen.add(mid)

                if sender == self.auth.username: continue

                # Verify signature
                sig = p.get("signature")
                if sig and self.target_pub and sender == self.target_name:
                    pv = dict(p)
                    pv.pop("signature", None)
                    if not verify_payload_signature(self.target_pub, pv, sig):
                        text = "[⚠️ INVALID SIG] " + text

                self._add_bubble(sender, ts, text, False)
            except: continue

    def _add_system(self, msg: str):
        lbl = QLabel(f"<center><i style='color: #888;'>{msg}</i></center>")
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, lbl)

    def _add_bubble(self, sender: str, ts: str, text: str, is_me: bool):
        bubble = ChatBubble(sender, ts, text, is_me, self.dark_mode)

        container = QWidget()
        container_layout = QHBoxLayout()
        container_layout.setContentsMargins(0, 0, 0, 0)
        container.setLayout(container_layout)

        if is_me:
            container_layout.addStretch()
            container_layout.addWidget(bubble)
        else:
            container_layout.addWidget(bubble)
            container_layout.addStretch()

        self.chat_layout.insertWidget(self.chat_layout.count() - 1, container)
        QTimer.singleShot(50, lambda: self.scroll.verticalScrollBar().setValue(self.scroll.verticalScrollBar().maximum()))

    def _clear_chat(self):
        while self.chat_layout.count() > 1:
            item = self.chat_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _fmt_ts(self, ts: str) -> str:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.astimezone().strftime("%H:%M")
        except:
            return ts

    def update_theme(self, dark: bool):
        self.dark_mode = dark

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("E2E Chat")
        self.resize(1000, 700)
        self.dark_mode = False

        self.api = ApiClient(SERVER_URL, SERVER_CERTIFICATE_PATH)

        # Menu bar
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, toolbar)

        # Left: theme toggle
        self.theme_toggle = ThemeToggle(self.dark_mode)
        self.theme_toggle.toggled.connect(self._toggle_theme)
        toolbar.addWidget(self.theme_toggle)

        # Spacer to push Exit to the right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        toolbar.addWidget(spacer)

        # Right: exit button
        exit_btn = ExitButton()
        exit_btn.clicked.connect(self.close)
        toolbar.addWidget(exit_btn)

        # Stack
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.login_screen = LoginScreen(self.api, self._on_logged_in, self.dark_mode)
        self.chat_screen = ChatScreen(self.api, self._on_logout, self.dark_mode)

        self.stack.addWidget(self.login_screen)
        self.stack.addWidget(self.chat_screen)

        self._apply_theme()

    def _toggle_theme(self, dark: bool):
        self.dark_mode = dark
        self.theme_toggle.set_dark_mode(dark)
        self.chat_screen.update_theme(dark)
        self._apply_theme()

    def _apply_theme(self):
        self.setStyleSheet(get_stylesheet(self.dark_mode))

    def _on_logged_in(self, auth: AuthContext):
        self.chat_screen.start(auth)
        self.stack.setCurrentWidget(self.chat_screen)

    def _on_logout(self):
        self.stack.setCurrentWidget(self.login_screen)

def main():
    app = QApplication([])
    app.setStyle('Fusion')

    # Set app-wide font
    font = QFont("-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif")
    font.setPointSize(10)
    app.setFont(font)

    window = MainWindow()
    window.show()
    app.exec()

if __name__ == "__main__":
    main()