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

import base64
import json
import os
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

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


# ---------------------------------------------------------------------------
# Environment / paths
# ---------------------------------------------------------------------------

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
        Your server has a bug: route is missing leading slash:
            @app.get("users/{user_id}")

        It SHOULD be: /users/{user_id}
        We'll try both paths to be robust.
        """
        for path in (f"/users/{user_id}", f"users/{user_id}"):
            r = requests.get(f"{self.server_url}{path}", headers={"x-api-key": api_key}, verify=self.verify_path)
            if r.status_code == 200:
                pem = r.json()["public_key_cert"].encode("utf-8")
                return x509.load_pem_x509_certificate(pem)
        raise RuntimeError(f"Cannot fetch user cert for {user_id}. (Route might be broken in server)")

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


def encrypt_chat_payload(sender: str, recipient: str, text: str) -> tuple[bytes, bytes]:
    """
    Encrypt message payload using AES-CTR with random 256-bit key.

    ciphertext_blob format: nonce(16) || ciphertext
    """
    payload = {
        "sender": sender,
        "recipient": recipient,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "text": text,
    }
    plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")

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


# ---------------------------------------------------------------------------
# GUI Widgets
# ---------------------------------------------------------------------------

class LoginScreen(QWidget):
    """
    Login / register screen.

    Flow:
    1) Ensure local RSA keypair exists
    2) Build CSR and register (idempotent for demo)
    3) Request API key (encrypted) and decrypt using private key
    4) Sign and authenticate
    """

    def __init__(self, api: ApiClient, on_logged_in):
        super().__init__()
        self.api = api
        self.on_logged_in = on_logged_in

        self.setLayout(QVBoxLayout())

        title = QLabel("E2E Chat Client")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: 700; padding: 10px;")
        self.layout().addWidget(title)

        form = QFormLayout()
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("e.g. alice")
        self.username_edit.setMaxLength(32)

        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("local key password")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setText("password123")  # project default

        form.addRow("Username:", self.username_edit)
        form.addRow("Key password:", self.password_edit)
        self.layout().addLayout(form)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.layout().addWidget(self.status)

        self.login_btn = QPushButton("Register / Login")
        self.login_btn.clicked.connect(self._login_clicked)
        self.layout().addWidget(self.login_btn)

        foot = QLabel(f"Server: {SERVER_URL} | Key storage: {PRIVATEKEY_STORAGE_PATH}")
        foot.setStyleSheet("color: #666; font-size: 11px;")
        self.layout().addWidget(foot)

        self.layout().addStretch(1)

    def _set_busy(self, busy: bool, msg: str = "") -> None:
        self.login_btn.setEnabled(not busy)
        self.username_edit.setEnabled(not busy)
        self.password_edit.setEnabled(not busy)
        self.status.setText(msg)

    def _login_clicked(self) -> None:
        username = self.username_edit.text().strip()
        password = self.password_edit.text()
        
        # --- username validation ---
        if len(username) > 32:
            warn(self, "Invalid username", "Username must be at most 32 characters.")
            return
        
        # alphanumeric only (letters+digits), no spaces, no underscores
        if not username.isalnum():
            warn(self, "Invalid username", "Username must be alphanumeric (letters and digits only).")
            return

        # empty fields
        if not username:
            warn(self, "Missing username", "Please enter a username.")
            return
        if not password:
            warn(self, "Missing password", "Please enter a password for local private key encryption.")
            return

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


class ChatScreen(QWidget):
    """
    Chat UI:
    - Shows logged in user
    - Dropdown lists all other users (/users)
    - Select one to chat with
    - Polls /messages/{user_id}
    """

    def __init__(self, api: ApiClient, on_logout):
        super().__init__()
        self.api = api
        self.on_logout = on_logout

        self.auth: Optional[AuthContext] = None

        # currently selected chat target
        self.target_user_id: Optional[str] = None
        self.target_username: Optional[str] = None
        self.target_pub: Optional[RSAPublicKey] = None

        # for not repeating messages
        self.seen_message_ids: set[str] = set()

        self.setLayout(QVBoxLayout())

        # Top bar
        top = QHBoxLayout()
        self.me_label = QLabel("Logged in as: -")
        self.me_label.setStyleSheet("font-weight: 700;")
        top.addWidget(self.me_label)
        top.addStretch(1)

        self.refresh_users_btn = QPushButton("Refresh users")
        self.refresh_users_btn.clicked.connect(self._refresh_users)
        top.addWidget(self.refresh_users_btn)

        self.logout_btn = QPushButton("Logout")
        self.logout_btn.clicked.connect(self._logout_clicked)
        top.addWidget(self.logout_btn)

        self.layout().addLayout(top)

        # User dropdown row
        row = QHBoxLayout()
        row.addWidget(QLabel("Chat with:"))

        self.user_combo = QComboBox()
        self.user_combo.setMinimumWidth(250)
        row.addWidget(self.user_combo, 1)

        self.connect_btn = QPushButton("Select")
        self.connect_btn.clicked.connect(self._select_target_from_combo)
        row.addWidget(self.connect_btn)

        self.layout().addLayout(row)

        # Chat history
        self.chat_view = QTextBrowser()
        self.chat_view.setStyleSheet("font-family: Consolas, monospace;")
        self.layout().addWidget(self.chat_view, 1)

        # Composer
        compose = QHBoxLayout()
        self.msg_edit = QTextEdit()
        self.msg_edit.setFixedHeight(70)
        self.msg_edit.setPlaceholderText("Type message...")
        compose.addWidget(self.msg_edit, 1)

        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self._send_clicked)
        compose.addWidget(self.send_btn)

        self.layout().addLayout(compose)

        self.status = QLabel("")
        self.status.setStyleSheet("color: #666;")
        self.layout().addWidget(self.status)

        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._poll)

        self._set_enabled(False)

    def start(self, auth: AuthContext) -> None:
        self.auth = auth
        self.me_label.setText(f"Logged in as: {auth.username}")
        self.chat_view.clear()
        self.seen_message_ids.clear()

        self.target_user_id = None
        self.target_username = None
        self.target_pub = None

        self._set_enabled(True)
        self.timer.start()
        self.status.setText("Click Refresh users, select a user, then Select.")

        # auto refresh once on entry
        self._refresh_users()

    def stop(self) -> None:
        self.timer.stop()
        self.auth = None
        self.target_user_id = None
        self.target_username = None
        self.target_pub = None
        self._set_enabled(False)
        self.chat_view.clear()
        self.status.setText("")
        self.user_combo.clear()

    def _set_enabled(self, enabled: bool) -> None:
        self.refresh_users_btn.setEnabled(enabled)
        self.user_combo.setEnabled(enabled)
        self.connect_btn.setEnabled(enabled)
        self.msg_edit.setEnabled(enabled)
        self.send_btn.setEnabled(enabled)
        self.logout_btn.setEnabled(enabled)

    def _logout_clicked(self) -> None:
        if not self.auth:
            return
        try:
            self.api.logout(self.auth.api_key)
        except Exception:
            pass
        self.stop()
        self.on_logout()

    def _refresh_users(self) -> None:
        """
        Fetch /users and populate the combo.
        We store user_id in Qt item data so we don't lose the mapping.
        """
        if not self.auth:
            return
        try:
            self.status.setText("Fetching users...")
            users = self.api.list_users(self.auth.api_key)

            self.user_combo.clear()
            if not users:
                self.user_combo.addItem("(no other users)", None)
                self.status.setText("No other users registered yet.")
                return

            for u in users:
                self.user_combo.addItem(u["username"], u["id"])

            self.status.setText(f"Loaded {len(users)} user(s). Select one and press Select.")
        except Exception as e:
            err(self, "Users fetch failed", str(e))
            self.status.setText("")

    def _append_message(self, username: str, raw_ts: str, text: str) -> None:
        ts = self._pretty_ts(raw_ts)
        self.chat_view.append(
            f"<div><b>{self._escape(username)} - {self._escape(ts)}:</b><br>"
            f"{self._escape(text)}</div><br>"
        )

    def _select_target_from_combo(self) -> None:
        if not self.auth:
            return
    
        target_id = self.user_combo.currentData()
        target_name = self.user_combo.currentText()
    
        if not target_id:
            warn(self, "No user", "No target user available to chat with.")
            return
    
        try:
            self.status.setText("Fetching target certificate...")
            cert = self.api.get_user_cert(self.auth.api_key, str(target_id))
    
            self.target_user_id = str(target_id)
            self.target_username = target_name
            self.target_pub = cert.public_key()
    
            # Reset UI for this chat view
            self.chat_view.clear()
            self.seen_message_ids.clear()
            self._append_system(f"Selected chat target: {target_name}")
    
            # Immediately load & render history ONCE (so poll won't re-print it)
            msgs = self.api.receive_messages(self.auth.api_key, self.target_user_id)
            for m in msgs:
                mid = str(m.get("message_id", "")).strip()
                # idk if this happens
                if not mid:
                    continue
                self.seen_message_ids.add(mid)
    
                ciphertext_blob = b64d_url(m["ciphertext"])
                enc_key = b64d_url(m["enc_key"])
                aes_key = rsa_decrypt_key(self.auth.private_key, enc_key)
                payload = decrypt_chat_payload(ciphertext_blob, aes_key)
    
                sender = m.get("sender_username", payload.get("sender", "?"))
                text = payload.get("text", "")
                ts = m.get("timestamp", payload.get("timestamp", ""))
    
                # Render with your preferred format
                self._append_message(sender, ts, text)

            self.status.setText(f"Selected {target_name}. You can send messages now.")
    
        except Exception as e:
            err(self, "Select failed", str(e))
            self.status.setText("")


    def _send_clicked(self) -> None:
        if not self.auth:
            return
        if not self.target_user_id or not self.target_pub:
            warn(self, "No target", "Select a user from the dropdown first.")
            return

        text = self.msg_edit.toPlainText().strip()
        if not text:
            return
        self.msg_edit.clear()

        try:
            # 1) Encrypt payload with random AES key
            ciphertext_blob, aes_key = encrypt_chat_payload(
                sender=self.auth.username,
                recipient=self.target_username,
                text=text,
            )

            # 2) Encrypt AES key for sender (so sender can decrypt history)
            sender_pub = self.auth.private_key.public_key()
            enc_key_sender = rsa_encrypt_key(sender_pub, aes_key)

            # 3) Encrypt AES key for receiver (so receiver can decrypt message)
            enc_key_receiver = rsa_encrypt_key(self.target_pub, aes_key)

            # 4) Build keys list expected by server
            keys_payload = [
                {
                    "encryption_key": b64e_url(enc_key_sender),
                    "user_id": self.auth.user_id,
                },
                {
                    "encryption_key": b64e_url(enc_key_receiver),
                    "user_id": self.target_user_id,
                },
            ]

            # 5) POST /messages/send
            ts = datetime.now(timezone.utc).isoformat()
            self.api.send_message(
                api_key=self.auth.api_key,
                recipient_id=self.target_user_id,
                ciphertext_blob=ciphertext_blob,
                keys=keys_payload,
                timestamp_iso=ts,
            )

            self._append_me(text)
            self.status.setText("Sent.")
        except Exception as e:
            err(self, "Send failed", str(e))
            self.status.setText("")

    def _poll(self) -> None:
        if not self.auth or not self.target_user_id:
            return
    
        try:
            msgs = self.api.receive_messages(self.auth.api_key, self.target_user_id)
        except Exception as e:
            self.status.setText(f"Receive error: {e}")
            return
    
        new_count = 0
        for m in msgs:
            mid = str(m.get("message_id", "")).strip()
            if not mid or mid in self.seen_message_ids:
                continue
            self.seen_message_ids.add(mid)
    
            try:
                ciphertext_blob = b64d_url(m["ciphertext"])
                enc_key = b64d_url(m["enc_key"])
                aes_key = rsa_decrypt_key(self.auth.private_key, enc_key)
    
                payload = decrypt_chat_payload(ciphertext_blob, aes_key)
    
                sender = m.get("sender_username", payload.get("sender", "?"))
                text = payload.get("text", "")
    
                # prefer server timestamp (it is authoritative for ordering),
                # fallback to payload timestamp if missing
                raw_ts = m.get("timestamp") or payload.get("timestamp") or ""
    
                # skip our own messages (we already show them on send)
                if sender == self.auth.username:
                    continue
    
                self._append_them(sender, raw_ts, text)
                new_count += 1
    
            except Exception:
                continue
    
        if new_count:
            self.status.setText(f"Received {new_count} new message(s).")


    # ---- rendering helpers ----
    def _append_system(self, text: str) -> None:
        self.chat_view.append(f"<div style='color:#666'>[system] {text}</div>")

    def _append_me(self, text: str) -> None:
        me = self.auth.username if self.auth else "me"
        raw_ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._append_message(me, raw_ts, text)
    
    def _append_them(self, sender: str, raw_ts: str, text: str) -> None:
        self._append_message(sender, raw_ts, text)

        
    def _pretty_ts(self, ts: str) -> str:
        try:
            # handles "...+00:00" and also "Z"
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ts


    @staticmethod
    def _escape(s: str) -> str:
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br>")
        )


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("E2E Chat (PyQt6)")
        self.resize(900, 600)

        self.api = ApiClient(SERVER_URL, SERVER_CERTIFICATE_PATH)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.login_screen = LoginScreen(self.api, self._on_logged_in)
        self.chat_screen = ChatScreen(self.api, self._on_logout)

        self.stack.addWidget(self.login_screen)
        self.stack.addWidget(self.chat_screen)
        self.stack.setCurrentWidget(self.login_screen)

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        self.menuBar().addAction(exit_action)

    def _on_logged_in(self, auth: AuthContext) -> None:
        self.chat_screen.start(auth)
        self.stack.setCurrentWidget(self.chat_screen)

    def _on_logout(self) -> None:
        self.stack.setCurrentWidget(self.login_screen)


def main() -> None:
    app = QApplication([])
    w = MainWindow()
    w.show()
    app.exec()


if __name__ == "__main__":
    main()
