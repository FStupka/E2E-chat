import os, uuid, hmac, hashlib, base64
from datetime import datetime, timedelta, timezone

import uvicorn
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from models import Base, User, Conversation, Message, MessageKey

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.exceptions import InvalidSignature

from dotenv import load_dotenv
import os

# Load .env file
load_dotenv()  # by default, it looks for a file named ".env" in the current directory

# Access environment variables
db_user = os.getenv("POSTGRES_USER")
db_pass = os.getenv("POSTGRES_PASSWORD")
db_dat = os.getenv("POSTGRES_DB")
server_port = int(os.getenv("SERVER_PORT"))
server_privatekey_path = os.getenv("SERVER_PRIVATEKEY_PATH")
server_certificate_path = os.getenv("SERVER_CERTIFICATE_PATH")
DATABASE_URL = f"postgresql+psycopg2://{db_user}:{db_pass}@localhost:5432/{db_dat}"

SERVER_SECRET = b"super-secret-server-key"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

app = FastAPI()




def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_api_key(api_key: bytes) -> str:
    return hmac.new(SERVER_SECRET, api_key, hashlib.sha256).hexdigest()


# =========================
# Register
# =========================

class RegisterData(BaseModel):
    username: str
    public_key: str

@app.post("/register")
def register(data: RegisterData, db: Session = Depends(get_db)):
    try:
        public = serialization.load_pem_public_key(data.public_key.encode())
    except:
        raise HTTPException(400, "Invalid public key format")
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size <= 1024:
        raise HTTPException(400, "Public key if incorrect type")
    #return {"status": "registered"}
    user = db.query(User).filter_by(username=data.username).first()
    if user:
        raise HTTPException(409, "A user with this email is already registered.")

    user = User(username=data.username, public_key=data.public_key,
                api_key_hash="")
    try:
        db.add(user)
    except:
        raise HTTPException(500)
    db.commit()
    return {"status": "registered"}


# =========================
# Login Step 1
# =========================

class GetApiData(BaseModel):
    username: str
@app.post("/get_api")
def get_api(data: GetApiData, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=data.username).first()
    if not user:
        raise HTTPException(404, "User not found")

    api_key = base64.urlsafe_b64encode(os.urandom(32))
    user.api_key_hash = hash_api_key(api_key)
    user.api_key_expires = None
    db.commit()

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
def login_step2(data: AuthenticateData, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=data.username).first()
    if not user:
        raise HTTPException(404, "User not found")

    if user.api_key_expires is not None:
        raise HTTPException(401, "Api key was not requested")

    if hash_api_key(data.api_key.encode()) != user.api_key_hash:
        raise HTTPException(401, "Invalid API key")

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
        raise HTTPException(401, "Invalid signature")

    user.api_key_expires = datetime.now(timezone.utc) + timedelta(minutes=30)
    conversations = user.conversations
    for conversation in conversations:
        print(conversation.id)
        for message in conversation.messages:
            print(id)
    db.commit()
    # here get user data I need
    return {
        "id": str(user.id),
        "username": user.username,
        "public_key": user.public_key,
    }


# =========================
# Auth Dependency
# =========================
def get_current_user(x_api_key: str = Header(...), db: Session = Depends(get_db)):
    h = hash_api_key(x_api_key.encode())
    user = db.query(User).filter_by(api_key_hash=h).first()
    if not user or user.api_key_expires < datetime.now(timezone.utc):
        raise HTTPException(401, "Unauthorized")
    user.api_key_expires = datetime.now(timezone.utc) + timedelta(minutes=30)
    db.commit()
    return user


# =========================
# Send Message
# =========================
@app.post("/messages/send")
def send_message(
    to_user: str,
    ciphertext: bytes,
    enc_key_for_sender: bytes,
    enc_key_for_receiver: bytes,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    other = db.query(User).filter_by(username=to_user).first()
    if not other:
        raise HTTPException(404, "Recipient not found")

    # Enforce ordered pair
    a, b = sorted([current_user.id, other.id])
    conv = db.query(Conversation).filter_by(user_a=a, user_b=b).first()
    if not conv:
        conv = Conversation(user_a=a, user_b=b)
        db.add(conv)
        db.commit()
        db.refresh(conv)

    msg = Message(conversation_id=conv.id, sender_id=current_user.id, ciphertext=ciphertext)
    db.add(msg)
    db.commit()
    db.refresh(msg)

    db.add_all([
        MessageKey(message_id=msg.id, user_id=current_user.id, enc_key=enc_key_for_sender),
        MessageKey(message_id=msg.id, user_id=other.id, enc_key=enc_key_for_receiver),
    ])
    db.commit()

    return {"status": "sent", "message_id": str(msg.id)}


# =========================
# Receive Messages
# =========================
@app.get("/messages/receive")
def receive_messages(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    msgs = (
        db.query(Message, MessageKey)
        .join(MessageKey, Message.id == MessageKey.message_id)
        .filter(MessageKey.user_id == current_user.id)
        .order_by(Message.created_at)
        .all()
    )

    return [
        {
            "message_id": str(m.id),
            "conversation_id": str(m.conversation_id),
            "ciphertext": base64.b64encode(m.ciphertext).decode(),
            "enc_key": base64.b64encode(k.enc_key).decode(),
            "timestamp": m.created_at.isoformat(),
        }
        for m, k in msgs
    ]

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
        ssl_keyfile=server_privatekey_path
    )