import os, hmac, hashlib, base64
import ssl
from datetime import datetime, timedelta, timezone

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from starlette import status

from models import User, Conversation, Message, MessageKey

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Access environment variables
db_user = os.getenv("POSTGRES_USER")
db_pass = os.getenv("POSTGRES_PASSWORD")
db_dat = os.getenv("POSTGRES_DB")
server_port = int(os.getenv("SERVER_PORT"))
server_transport_privatekey_path = os.getenv("SERVER_TRANSPORT_PRIVATEKEY_PATH")
server_transport_certificate_path = os.getenv("SERVER_TRANSPORT_CERTIFICATE_PATH")
server_storage_privatekey_path = os.getenv("SERVER_STORAGE_PRIVATEKEY_PATH")
server_storage_certificate_path = os.getenv("SERVER_STORAGE_CERTIFICATE_PATH")
DATABASE_URL = f"postgresql+asyncpg://{db_user}:{db_pass}@localhost:5432/{db_dat}"

SERVER_SECRET = b"super-secret-server-key"
with open(server_storage_privatekey_path, "rb") as key_file:
    data = key_file.read()
storage_private_key = serialization.load_pem_private_key(data, password=None)
with open(server_storage_certificate_path, "rb") as cert_file:
    data = cert_file.read()
storage_cert = x509.load_pem_x509_certificate(data)

engine = create_async_engine(DATABASE_URL, echo=False)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

app = FastAPI()




async def get_db():
    async with AsyncSessionLocal() as db:
        yield db

# Todo: think about diferent algorithm
def hash_api_key(api_key: bytes) -> str:
    return hmac.new(SERVER_SECRET, api_key, hashlib.sha256).hexdigest()

def certificate_validator(cert: x509.Certificate, username: str) -> bool:
    storage_public_key = storage_cert.public_key()
    time_now = datetime.now(timezone.utc)
    if storage_cert.subject != cert.issuer:
        return False
    if cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value != username:
        return False
    if cert.not_valid_before_utc > time_now or cert.not_valid_after_utc < time_now:
        return False
    try:
        storage_public_key.verify(cert.signature,
                          cert.tbs_certificate_bytes,
                          padding.PKCS1v15(),
                          hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def extend_cert(cert: x509.Certificate) -> x509.Certificate:
    not_before = datetime.now(timezone.utc)
    not_after = datetime.now(timezone.utc) + timedelta(days=365)

    builder = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .issuer_name(cert.issuer)
        .public_key(cert.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # Copy extensions
    for ext in cert.extensions:
        builder = builder.add_extension(ext.value, ext.critical)
    new_cert = builder.sign(private_key=storage_private_key, algorithm=hashes.SHA256(), rsa_padding=padding.PKCS1v15())
    return new_cert


# registration
class RegisterData(BaseModel):
    username: str
    csr: str

@app.post("/register")
async def register(data: RegisterData, db: AsyncSession = Depends(get_db)):
    try:
        csr = x509.load_pem_x509_csr(data.csr.encode())
    except:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Invalid public key format")
    if not isinstance(csr.public_key(), rsa.RSAPublicKey) or csr.public_key().key_size != 4096:
        raise HTTPException(status.HTTP_417_EXPECTATION_FAILED, "Public key if incorrect type")

    result = await db.execute(
        select(User).where(User.username == data.username)
    )
    user = result.scalar_one_or_none()
    if user:
        raise HTTPException(status.HTTP_409_CONFLICT, "A user with this email is already registered.")

    if csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value != data.username:
        raise HTTPException(status.HTTP_409_CONFLICT, "Not same username in CSR")
    certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(storage_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(private_key=storage_private_key, algorithm=hashes.SHA256(), rsa_padding=padding.PKCS1v15())
    )

    certificate_str = certificate.public_bytes(encoding=serialization.Encoding.PEM).decode()

    try:
        user = User(username=data.username, public_key_cert=certificate_str,
                    api_key_hash="!")
        db.add(user)
        await db.commit()
    except:
        await db.rollback()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")
    return {"status": "registered"}


# =========================
# Login Step 1
# =========================

class GetApiData(BaseModel):
    username: str
@app.post("/get_api")
async def get_api(data: GetApiData, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(User).where(User.username == data.username)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    api_key = base64.urlsafe_b64encode(os.urandom(32))

    try:
        user.api_key_hash = hash_api_key(api_key)
        user.api_key_created = datetime.now(timezone.utc)
        user.api_key_expires = None
        await db.commit()
        await db.refresh(user)
    except:
        await db.rollback()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")

    cert = x509.load_pem_x509_certificate(user.public_key_cert.encode())
    if not certificate_validator(cert, user.username):
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Public key is corrupted")

    encrypted_api = base64.urlsafe_b64encode(cert.public_key().encrypt(api_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )).decode()

    return {"api_key": encrypted_api}


# =========================
# Login Step 2
# =========================

class AuthenticateData(BaseModel):
    username: str
    api_key: str
    timestamp: str
    signature: str

@app.post("/authenticate")
async def authenticate(data: AuthenticateData, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(User).options(selectinload(User.conversations).selectinload(Conversation.messages)).where(User.username == data.username)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    if user.api_key_expires is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Api key was not requested")

    time_now = datetime.now(timezone.utc)
    timestamp = datetime.fromisoformat(data.timestamp)
    if time_now < timestamp or timestamp + timedelta(minutes=1) < time_now:
        raise HTTPException(status.HTTP_417_EXPECTATION_FAILED, "Timestamp is older then 1 minute")
    if user.api_key_created is None or timestamp < user.api_key_created or user.api_key_created + timedelta(minutes=5) < timestamp:
        raise HTTPException(status.HTTP_417_EXPECTATION_FAILED, "Timestamp not enough fresh for API key")

    if hash_api_key(data.api_key.encode()) != user.api_key_hash:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")
    # Verify signature(api_key)

    cert = x509.load_pem_x509_certificate(user.public_key_cert.encode())
    if not certificate_validator(cert, user.username):
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Public key is corrupted")

    pub : RSAPublicKey = cert.public_key()

    signed_data = f"{data.timestamp} - {data.api_key}".encode()

    try:
        pub.verify(base64.urlsafe_b64decode(data.signature.encode()), signed_data,
                   padding.PSS(
                       mgf=padding.MGF1(hashes.SHA256()),
                       salt_length=padding.PSS.MAX_LENGTH
                   ),
                   hashes.SHA256()
                   )
    except InvalidSignature:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid signature")


    try:
        user.api_key_expires = datetime.now(timezone.utc) + timedelta(minutes=30)
        if time_now + timedelta(days=30) > cert.not_valid_after_utc:
            user.public_key_cert = extend_cert(cert).public_bytes(encoding=serialization.Encoding.PEM).decode()
        await db.commit()
        await db.refresh(user)
    except:
        await db.rollback()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")

    # here get user data I need
    return {
        "status": "authenticated",
        "user_id": user.id
    }


# =========================
# Auth Dependency
# =========================
async def get_current_user(x_api_key: str = Header(...), db: AsyncSession = Depends(get_db)):
    h = hash_api_key(x_api_key.encode())
    result = await db.execute(
        select(User).where(User.api_key_hash == h)
    )
    user = result.scalar_one_or_none()
    if not user or user.api_key_expires < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unauthorized")
    try:
        user.api_key_expires = datetime.now(timezone.utc) + timedelta(minutes=30)
        await db.commit()
        await db.refresh(user)
    except:
        await db.rollback()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")
    return user


# logout
@app.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    try:
        current_user.api_key_expires = datetime.now(timezone.utc)
        await db.commit()
    except:
        await db.rollback()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")
    return {"status": "logged out"}

# =========================
# Send Message
# =========================
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
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(User).where(User.id == data.recipient_id)
    )
    recipient = result.scalar_one_or_none()
    if not recipient:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Recipient not found")

    # Enforce ordered pair
    a, b = sorted([current_user.id, recipient.id])
    result = await db.execute(
        select(Conversation).where(Conversation.user_a == a, Conversation.user_b == b)
    )
    conv = result.scalar_one_or_none()
    if not conv:
        conv = Conversation(user_a=a, user_b=b)
        try:
            db.add(conv)
            await db.commit()
            await db.refresh(conv)
        except:
            await db.rollback()
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")


    msg = Message(
        conversation_id=conv.id,
        sender_id=current_user.id,
        ciphertext=base64.urlsafe_b64decode(data.ciphertext.encode()),
        created_at=datetime.fromisoformat(data.timestamp),
    )
    try:
        db.add(msg)
        await db.flush()
        await db.refresh(msg)


        message_keys = [
            MessageKey(
                message_id=msg.id,
                user_id=key.user_id,
                enc_key=base64.urlsafe_b64decode(key.encryption_key.encode())
            )
            for key in data.keys
        ]

        db.add_all(message_keys)
        await db.commit()
    except:
        await db.rollback()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")

    return {"status": "sent"}

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


# =========================
# Receive Messages
# =========================
@app.get("/messages/{user_id}")
async def receive_messages(target_user: User = Depends(get_target_user), current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    a, b = sorted([current_user.id, target_user.id])

    result = await db.execute(
        select(Conversation)
        .where(Conversation.user_a == a, Conversation.user_b == b)
    )
    conv = result.scalar_one_or_none()
    if not conv:
        return []

    result = await db.execute(
        select(Message, MessageKey)
        .join(MessageKey, Message.id == MessageKey.message_id)
        .filter(MessageKey.user_id == current_user.id, Message.conversation_id == conv.id)
        .order_by(Message.created_at)
    )
    msgs = result.all()

    return [
        {
            "message_id": str(m.id),
            "sender_username": m.sender.username,
            "ciphertext": base64.urlsafe_b64encode(m.ciphertext).decode(),
            "enc_key": base64.urlsafe_b64encode(k.enc_key).decode(),
            "timestamp": m.created_at.isoformat(),
        }
        for m, k in msgs
    ]

@app.get("/users")
async def users(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(User)
        .filter(User.id != current_user.id)
        .order_by(User.username)
    )
    users = result = await db.execute(
    select(User).filter(User.id != current_user.id).order_by(User.username))
    users = result.scalars().all()

    return [
        {
            "id": str(u.id),
            "username": u.username
        }
        for u in users
    ]

@app.get("/users/{user_id}")
async def user_by_username(target_user: User = Depends(get_target_user), current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(User)
        .filter(User.username == target_user.username)
    )
    user = result.scalar_one_or_none()
    return {
        "username": user.username,
        "public_key_cert": user.public_key_cert,
    }

@app.get("/")
def hello():
    return {"message": "Hello, secure world!"}

if __name__ == "__main__":
    # Paths to your certificate and private key

    # Run HTTPS server
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=server_port,
        ssl_certfile=server_transport_certificate_path,
        ssl_keyfile=server_transport_privatekey_path,
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
    )