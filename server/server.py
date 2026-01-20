import os, hmac, hashlib, base64
import ssl
from datetime import datetime, timedelta, timezone

import uvicorn
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
server_privatekey_path = os.getenv("SERVER_PRIVATEKEY_PATH")
server_certificate_path = os.getenv("SERVER_CERTIFICATE_PATH")
DATABASE_URL = f"postgresql+asyncpg://{db_user}:{db_pass}@localhost:5432/{db_dat}"

SERVER_SECRET = b"super-secret-server-key"

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


def hash_api_key(api_key: bytes) -> str:
    return hmac.new(SERVER_SECRET, api_key, hashlib.sha256).hexdigest()


# registration
class RegisterData(BaseModel):
    username: str
    public_key: str

@app.post("/register")
async def register(data: RegisterData, db: AsyncSession = Depends(get_db)):
    try:
        public = serialization.load_pem_public_key(data.public_key.encode())
    except:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Invalid public key format")
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size <= 1024:
        raise HTTPException(status.HTTP_417_EXPECTATION_FAILED, "Public key if incorrect type")

    result = await db.execute(
        select(User).where(User.username == data.username)
    )
    user = result.scalar_one_or_none()
    if user:
        raise HTTPException(status.HTTP_409_CONFLICT, "A user with this email is already registered.")


    try:
        user = User(username=data.username, public_key=data.public_key,
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
    pub = serialization.load_pem_public_key(user.public_key.encode())

    encrypted_api = base64.urlsafe_b64encode(pub.encrypt(api_key,
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
    print(timestamp)
    print(time_now)
    if time_now < timestamp or timestamp + timedelta(minutes=1) < time_now:
        raise HTTPException(status.HTTP_417_EXPECTATION_FAILED, "Timestamp is older then 1 minute")
    if timestamp < user.api_key_created or user.api_key_created + timedelta(minutes=5) < timestamp:
        raise HTTPException(status.HTTP_417_EXPECTATION_FAILED, "Timestamp not enough fresh for API key")

    if hash_api_key(data.api_key.encode()) != user.api_key_hash:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")
    # Verify signature(api_key)
    pub : RSAPublicKey = serialization.load_pem_public_key(user.public_key.encode())

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
        await db.commit()
        await db.refresh(user)
    except:
        await db.rollback()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")

    # here get user data I need
    return {
        "status": "authenticated",
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
        ciphertext=base64.urlsafe_b64decode(data.ciphertext.encode())
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
    users = result.all()
    return [
        {
            "id": str(u.id),
            "username": u.username
        }
        for u in users
    ]

@app.get("users/{user_id}")
async def user_by_username(target_user: User = Depends(get_target_user), current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(User)
        .filter(User.username == target_user.username)
    )
    user = result.scalar_one_or_none()
    return {
        "username": user.username,
        "public_key": user.public_key,
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
        ssl_certfile=server_certificate_path,
        ssl_keyfile=server_privatekey_path,
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
    )