from __future__ import annotations
import os, base64
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from starlette import status
from models import User, Conversation, Message, MessageKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent


#### Loading environmental variables ####
load_dotenv(BASE_DIR / ".env")

DB_USER = os.getenv("POSTGRES_USER", "admin")
DB_PASS = os.getenv("POSTGRES_PASSWORD")
DB_DAT = os.getenv("POSTGRES_DB", "E2E-chat")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8088"))
SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_TRANSPORT_PRIVATEKEY_PATH = os.getenv("SERVER_TRANSPORT_PRIVATEKEY_PATH")
SERVER_TRANSPORT_CERTIFICATE_PATH = os.getenv("SERVER_TRANSPORT_CERTIFICATE_PATH")
SERVER_STORAGE_PRIVATEKEY_PATH = os.getenv("SERVER_STORAGE_PRIVATEKEY_PATH")
SERVER_STORAGE_CERTIFICATE_PATH = os.getenv("SERVER_STORAGE_CERTIFICATE_PATH")

DATABASE_URL = f"postgresql+asyncpg://{DB_USER}:{DB_PASS}@localhost:5432/{DB_DAT}"

with open(SERVER_STORAGE_PRIVATEKEY_PATH, "rb") as key_file:
    d = key_file.read()
STORAGE_PRIVATE_KEY = serialization.load_pem_private_key(d, password=None)
with open(SERVER_STORAGE_CERTIFICATE_PATH, "rb") as cert_file:
    d = cert_file.read()
STORAGE_CERT = x509.load_pem_x509_certificate(d)


#### Database related ####
engine = create_async_engine(DATABASE_URL, echo=False)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


#### FastAPI related ####
app = FastAPI()


#### General helping functions ####
def b64e_url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")


def b64d_url(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s.encode("utf-8"))
    except:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Data is not base64 encoded")


def tse_iso(dt: datetime) -> str:
    return dt.isoformat()


def tsd_iso(s: str) -> datetime:
    try:
        return datetime.fromisoformat(s)
    except:
        raise HTTPException(status.HTTP_417_EXPECTATION_FAILED, "Timestamp in bad format")


#### API key helping functions ####
def api_derived_key(api_key: str) -> str:
    # Generate salt
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000
    )
    derived_key = kdf.derive(b64d_url(api_key))

    return b64e_url(salt+derived_key)


def api_key_checker(api_key: str, api_key_dk: str) -> bool:
    # Split stored data into salt and derived key
    salt = b64d_url(api_key_dk)[:16]
    stored_dk = b64d_url(api_key_dk)[16:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000
    )
    derived_key = kdf.derive(b64d_url(api_key))

    return derived_key == stored_dk


#### Certificate helping functions ####
def cert_validator(cert: x509.Certificate, username: str) -> bool:

    storage_public_key = STORAGE_CERT.public_key()
    time_now = datetime.now(timezone.utc)

    # Check issuer
    if STORAGE_CERT.subject != cert.issuer:
        return False
    # Check username (this app specific)
    if (cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME) and
            cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value != username):
        return False
    # Check validity
    if cert.not_valid_before_utc > time_now or cert.not_valid_after_utc < time_now:
        return False
    # Check signature
    try:
        storage_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except InvalidSignature:
        return False
    return True


def cert_extend(cert: x509.Certificate) -> x509.Certificate:
    not_before = datetime.now(timezone.utc)
    not_after = datetime.now(timezone.utc) + timedelta(days=365)

    # Copy certificate and add new validity
    builder = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .issuer_name(cert.issuer)
        .public_key(cert.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    for ext in cert.extensions:
        builder = builder.add_extension(ext.value, ext.critical)

    # Sign new certificate
    new_cert = builder.sign(
        private_key=STORAGE_PRIVATE_KEY,
        algorithm=hashes.SHA256(),
        rsa_padding=padding.PKCS1v15()
    )

    return new_cert


#### API helping functions ####
# Get db client
async def get_db():
    async with AsyncSessionLocal() as db:
        yield db


class CurrentUserData(BaseModel):
    username: str

async def get_current_user(
    data: CurrentUserData,
    db: AsyncSession = Depends(get_db)
):
    # Check username format
    if not data.username or not data.username.isalnum() or len(data.username) > 32:
        raise HTTPException(status.HTTP_417_EXPECTATION_FAILED, "Username format is wrong")

    # Look for user with this username
    result = await db.execute(
        select(User).where(User.username == data.username)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    return user

# Get user with specific id
async def get_target_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user not found"
        )

    return user


# Current user search and authentication
async def get_authenticated_user(
    x_api_key: str = Header(...),
    x_user_id: str = Header(...),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(User).where(User.id == x_user_id))
    user = result.scalar_one_or_none()

    # No user
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unauthorized")
    # Never get_api or invalid api key
    if user.api_key_dk == user.username or not api_key_checker(x_api_key, user.api_key_dk):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unauthorized")
    # Not authenticated or api key expired
    if user.api_key_expires is None or user.api_key_expires < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unauthorized")

    try:
        # Extend api key expiration
        user.api_key_expires = datetime.now(timezone.utc) + timedelta(minutes=30)
        await db.commit()
        await db.refresh(user)
    except:
        await db.rollback()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")

    return user


#### API ####
# Registration
class RegisterData(BaseModel):
    username: str
    csr: str

@app.post("/register")
async def register(
    data: RegisterData,
    db: AsyncSession = Depends(get_db)
):
    # Check username format
    if not data.username or not data.username.isalnum() or len(data.username) > 32:
        raise HTTPException(status.HTTP_417_EXPECTATION_FAILED, "Username format is wrong")
    
    # Parse CSR
    try:
        csr = x509.load_pem_x509_csr(data.csr.encode("utf-8"))
    except Exception:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid CSR")   #payload is invalid
    
    # Check if public key in CSR meets conditions
    if not isinstance(csr.public_key(), rsa.RSAPublicKey) or csr.public_key().key_size != 4096:
        raise HTTPException(status.HTTP_417_EXPECTATION_FAILED, "Public key if incorrect type")

    # Check for username uniqueness
    result = await db.execute(
        select(User).where(User.username == data.username)
    )
    user = result.scalar_one_or_none()
    if user:
        raise HTTPException(status.HTTP_409_CONFLICT, "A user with this username is already registered")

    # Check if username meets username in CSR (CN must exist and must match username)
    cn_attrs = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not cn_attrs:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "CSR must contain CN")
    if cn_attrs[0].value != data.username:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "CSR CN must match username")
    
    # Validate CSR signature (proof of private key ownership)
    try:
        if hasattr(csr, "is_signature_valid"):
            if not csr.is_signature_valid:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "CSR signature invalid")
        else:
            csr.public_key().verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                padding.PKCS1v15(),
                csr.signature_hash_algorithm,
            )
    except InvalidSignature:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "CSR signature invalid")
    except Exception:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "CSR signature invalid")

    # Create certificate
    not_before = datetime.now(timezone.utc)
    not_after = datetime.now(timezone.utc) + timedelta(days=365)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(STORAGE_CERT.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
    )
    cert = builder.sign(
            private_key=STORAGE_PRIVATE_KEY,
            algorithm=hashes.SHA256(),
            rsa_padding=padding.PKCS1v15()
        )

    certificate_str = cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode("utf-8")

    # Create user in database
    try:
        user = User(username=data.username, public_key_cert=certificate_str,
                    api_key_dk=data.username)
        db.add(user)
        await db.commit()
    except:
        await db.rollback()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")

    return {
    "status": "Registered",
    "user_id": str(user.id),
    "public_key_cert": certificate_str,
    }   

# Get api key (login step 1)
@app.post("/get_api")
async def get_api(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Check correctness of user certificate stored
    cert = x509.load_pem_x509_certificate(current_user.public_key_cert.encode("utf-8"))
    if not cert_validator(cert, current_user.username):
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Public key is corrupted")

    # Generate API key
    api_key = b64e_url(os.urandom(32))

    # Encrypt API key
    encrypted_api = b64e_url(
        cert.public_key().encrypt(
            api_key.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    )

    # Write API derived key
    try:
        current_user.api_key_dk = api_derived_key(api_key)
        current_user.api_key_created = datetime.now(timezone.utc)
        current_user.api_key_expires = None
        await db.commit()
        await db.refresh(current_user)
    except:
        await db.rollback()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")

    return {"api_key": encrypted_api}


# Authenticate api key (login step 2)
class AuthenticateData(BaseModel):
    api_key: str
    timestamp: str
    signature: str

@app.post("/authenticate")
async def authenticate(
    data: AuthenticateData,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Check correctness of user certificate stored
    cert = x509.load_pem_x509_certificate(current_user.public_key_cert.encode("utf-8"))
    if not cert_validator(cert, current_user.username):
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Public key is corrupted")

    # Check if he called get_api first
    if current_user.api_key_created is None or current_user.api_key_expires is not None:
        raise HTTPException(status.HTTP_412_PRECONDITION_FAILED, "Api key was not requested")

    time_now = datetime.now(timezone.utc)
    timestamp = tsd_iso(data.timestamp)

    # Check if timestamp is max 1 minute old (freshness)
    if time_now < timestamp or timestamp + timedelta(minutes=1) < time_now:
        raise HTTPException(status.HTTP_417_EXPECTATION_FAILED, "Timestamp is older then 1 minute")
    # Check whether timestamp is max 5 minutes older than API key creation
    if timestamp < current_user.api_key_created or current_user.api_key_created + timedelta(minutes=5) < timestamp:
        raise HTTPException(status.HTTP_417_EXPECTATION_FAILED, "Timestamp not enough fresh for API key")

    # Verify signature
    pub : RSAPublicKey = cert.public_key()
    signed_data = f"{data.timestamp} - {data.api_key}".encode("utf-8")
    try:
        pub.verify(
            b64d_url(data.signature),
            signed_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unauthorized")


    # check API key
    if not api_key_checker(data.api_key, current_user.api_key_dk):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unauthorized")


    try:
        # Set API key expiration to 30 mins
        current_user.api_key_expires = datetime.now(timezone.utc) + timedelta(minutes=30)
        # Extend user certificate if valid less than 30 days, user just proved his private key ownership
        if time_now + timedelta(days=30) > cert.not_valid_after_utc:
            current_user.public_key_cert = cert_extend(cert).public_bytes(
                encoding=serialization.Encoding.PEM
            ).decode("utf-8")

        await db.commit()
        await db.refresh(current_user)
    except:
        await db.rollback()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")

    return {
        "status": "Authenticated",
        "user_id": current_user.id
    }


# logout
@app.post("/logout")
async def logout(
    authenticated_user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db)
):
    try:
        authenticated_user.api_key_expires = datetime.now(timezone.utc)
        await db.commit()
    except:
        await db.rollback()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")
    return {"status": "Logged out"}


# Send Message
class EncryptionKeyData(BaseModel):
    encryption_key: str
    user_id: str

class MessageData(BaseModel):
    ciphertext: str
    keys: list[EncryptionKeyData]
    recipient_id: str
    timestamp: str

@app.post("/messages/send")
async def send_message(
    data: MessageData,
    authenticated_user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db)
):
    # Find recipient
    result = await db.execute(
        select(User).where(User.id == data.recipient_id)
    )
    recipient = result.scalar_one_or_none()
    if not recipient:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Recipient not found")

    # Enforce ordered pair
    a, b = sorted([authenticated_user.id, recipient.id])
    # Find conversation
    result = await db.execute(
        select(Conversation).where(Conversation.user_a == a, Conversation.user_b == b)
    )
    conv = result.scalar_one_or_none()
    # Create conversation if not existing
    if not conv:
        try:
            conv = Conversation(user_a=a, user_b=b)
            db.add(conv)
            await db.commit()
            await db.refresh(conv)
        except:
            await db.rollback()
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")


    try:
        msg = Message(
            conversation_id=conv.id,
            sender_id=authenticated_user.id,
            ciphertext=b64d_url(data.ciphertext),
            created_at=datetime.fromisoformat(data.timestamp),
        )
        db.add(msg)
        await db.flush()
        await db.refresh(msg)


        message_keys = [
            MessageKey(
                message_id=msg.id,
                user_id=key.user_id,
                enc_key=b64d_url(key.encryption_key)
            )
            for key in data.keys
        ]

        db.add_all(message_keys)
        await db.commit()
    except:
        await db.rollback()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")

    return {"status": "sent"}


# Receive Messages
@app.get("/messages/{user_id}")
async def receive_messages(
    target_user: User = Depends(get_target_user),
    authenticated_user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db)
):
    # Enforce ordered pair
    a, b = sorted([authenticated_user.id, target_user.id])
    # Look for this users conversation
    result = await db.execute(
        select(Conversation)
        .where(Conversation.user_a == a, Conversation.user_b == b)
    )
    conv = result.scalar_one_or_none()

    if not conv:
        return []

    # List conversation messages and message keys for current user
    result = await db.execute(
        select(Message, MessageKey)
        .join(MessageKey, Message.id == MessageKey.message_id)
        .filter(MessageKey.user_id == authenticated_user.id, Message.conversation_id == conv.id)
        .order_by(Message.created_at)
    )
    msgs = result.all()

    return [
        {
            "message_id": str(m.id),
            "sender_id": m.sender_id,
            "ciphertext": b64e_url(m.ciphertext),
            "enc_key": b64e_url(k.enc_key),
            "timestamp": tse_iso(m.created_at),
        }
        for m, k in msgs
    ]


# List users
@app.get("/users")
async def users(
    authenticated_user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db)
):
    # Get all users except current user
    result = await db.execute(
        select(User)
        .filter(User.id != authenticated_user.id)
        .order_by(User.username)
    )
    users = result.scalars().all()

    return [
        {
            "user_id": str(u.id),
            "username": u.username
        }
        for u in users
    ]


# Find specific user
@app.get("/users/{user_id}")
async def user_by_username(
    target_user: User = Depends(get_target_user),
    authenticated_user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db)
):
    return {
        "user_id": str(target_user.id),
        "username": target_user.username,
        "public_key_cert": target_user.public_key_cert,
    }

if __name__ == "__main__":
    # Paths to your certificate and private key

    # Run HTTPS server
    uvicorn.run(
        app,
        host=SERVER_HOST,
        port=SERVER_PORT,
        ssl_certfile=SERVER_TRANSPORT_CERTIFICATE_PATH,
        ssl_keyfile=SERVER_TRANSPORT_PRIVATEKEY_PATH,
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
    )