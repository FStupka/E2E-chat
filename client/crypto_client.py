import base64
import os
from datetime import timezone, datetime
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from dotenv import load_dotenv


# Load .env file
load_dotenv()  # by default, it looks for a file named ".env" in the current directory

# Access environment variables
server_address = os.getenv("SERVER_ADDRESS")
server_port = int(os.getenv("SERVER_PORT"))
privatekey_storage = Path(os.getenv("PRIVATEKEY_STORAGE"))

server_transport_cert_path = os.getenv("SERVER_TRANSPORT_CERTIFICATE_PATH")
server_storage_cert_path = Path(os.getenv("SERVER_STORAGE_CERTIFICATE_PATH"))

SERVER_URL= f"https://{server_address}:{server_port}"

def base64_to_bytes(string):
    return base64.urlsafe_b64decode(string.encode())

def bytes_to_base64(data):
    return base64.urlsafe_b64encode(data).decode()

def generate_keypair(username: str):
# Generate RSA 4096-bit key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

# Serialize
    public_key = private_key.public_key()

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sardinia"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Cagliari"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "E2E-chat"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{username}"),
    ])).sign(private_key, hashes.SHA256())

    csr_pem_str = csr.public_bytes(
    encoding=serialization.Encoding.PEM,
    ).decode('utf-8')
    payload = {
        "username": username,
        "csr": csr_pem_str
    }
    response = requests.post(f"{SERVER_URL}/register", json=payload, verify=server_transport_cert_path)
    print(response, response.text)
    if response.status_code != 200:
        return None
    print(response.text)
    # ask for password
    password = "password123"

# Serialize and save the private key
    with open(privatekey_storage/ f"{username}_private.pem", "wb") as priv_file:
        priv_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())  # Change if you want password encryption
            )
        )
    print(f"RSA 4096-bit key pair generated and private saved to '{username}_private.pem'")

def login(username: str):
    # ask for password
    password = "password123"
    with open(privatekey_storage / f"{username}_private.pem", "rb") as key_file:
        private_key : RSAPrivateKey = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode()  # or provide a password if the key is encrypted
        )
        # part 1
        payload = {
            "username": username
        }

        response = requests.post(f"{SERVER_URL}/get_api", json=payload, verify=server_transport_cert_path)
        if response.status_code != 200:
            print(response.text, response.status_code)
            return
        data = response.json()
        encrypted_api_key = data.get("api_key")
        api_key = private_key.decrypt(base64_to_bytes(encrypted_api_key),padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )).decode()


        # part 2
        timestamp = datetime.now(timezone.utc).isoformat()
        data_to_sign = f"{timestamp} - {api_key}".encode()

        signature = bytes_to_base64(private_key.sign(data_to_sign,
                                     padding.PSS(
                                        mgf=padding.MGF1(hashes.SHA256()),
                                        salt_length=padding.PSS.MAX_LENGTH
                                     ),
                                     hashes.SHA256()))

        payload = {
            "timestamp": timestamp,
            "username": username,
            "api_key": api_key,
            "signature": signature
        }
        response = requests.post(f"{SERVER_URL}/authenticate", json=payload, verify=server_transport_cert_path)
        if response.status_code != 200:
            print(response.text, response.status_code)
            return
        data = response.json()

        return (private_key, private_key.public_key(), api_key)

def logout(api_key):
    headers = {
        "x-api-key": api_key
    }
    response = requests.post(f"{SERVER_URL}/logout", headers=headers, verify=server_transport_cert_path)
    if response.status_code != 200:
        print(response.text, response.status_code)
        return
    print("logout successful")

def send_message(private_key: RSAPrivateKey, public_key: RSAPublicKey, timestamp: datetime, sender: str, recipient: str, message: bytes):
    # sign
    data = f"{timestamp.isoformat()}||{sender}->{recipient}||".encode()+message
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signed_data = message + b"||" + signature
    # AES init
    aes_key = os.urandom(32)  # 256-bit key
    nonce = os.urandom(16)  # CTR nonce
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    # encryption
    ciphertext = encryptor.update(signed_data) + encryptor.finalize()

    # key encryption
    sender_encrypted_aes_key = private_key.public_key().encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    recipient_encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # data to send
    package = {
        "encrypted_keys": {
            f"{recipient}": bytes_to_base64(recipient_encrypted_aes_key),
            f"{sender}": bytes_to_base64(sender_encrypted_aes_key)
        },
        "nonce": bytes_to_base64(nonce),
        "context": bytes_to_base64(ciphertext),
        "sender": sender,
        "recipient": recipient,
        "timestamp": timestamp.isoformat(),
    }
    return package

def receive_message(
    private_key: RSAPrivateKey,
    sender_public_key: RSAPublicKey,
    timestamp: datetime,
    sender: str,
    recipient: str,
    package: dict
) -> bytes:
    # get data from package
    encrypted_aes_key = base64_to_bytes(package["encrypted_keys"][recipient])
    nonce = base64_to_bytes(package["nonce"])
    ciphertext = base64_to_bytes(package["context"])

    # decrypt aes key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # decrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    signed_data = decryptor.update(ciphertext) + decryptor.finalize()

    # split
    try:
        message, signature = signed_data.split(b"||", 1)
    except ValueError:
        raise ValueError("Invalid signed message format")

    # verification_payload
    data_to_verify = f"{timestamp.isoformat()}||{sender}->{recipient}||".encode() + message

    # signature verification
    try:
        sender_public_key.verify(
            signature,
            data_to_verify,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        raise ValueError("Signature verification failed")


    return message

if __name__ == "__main__":
    generate_keypair("admin")
    priv, pub, api_key = login("admin")
    #ap = "fi8U5UqgAh7FAClapWUuDvgjNkRcddA_Mtg22RZ1Nbs="
    #print(api_key)
    logout(api_key)
    #logout(ap)
    #timestamp = datetime.now(timezone.utc)
    #pack = send_message(priv, pub, timestamp,"test1", "test1", b"hello")
    #ret = receive_message(priv, pub, timestamp,"test1", "test1", pack)

   # print(ret)