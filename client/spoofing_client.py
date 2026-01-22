import base64
import json
import os
from datetime import timezone, datetime
from pathlib import Path
from typing import Any

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
SERVER_URL= f"https://{server_address}:{server_port}"

def b64e_url(data: bytes) -> str:
    """urlsafe base64 (matches your server usage for ciphertext + keys)."""
    return base64.urlsafe_b64encode(data).decode("utf-8")


def b64d_url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("utf-8"))

def generate_keypair(username: str):
# Generate RSA 4096-bit key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

# Serialize
    public_key = private_key.public_key()

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
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
    with open(privatekey_storage/ f"{username}_private.pem", "wb") as priv_file:
        priv_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption("password123".encode())  # Change if you want password encryption
            )
        )
    return private_key

def legit_login(username, pk):

        # part 1
        payload = {
            "username": username
        }

        response = requests.post(f"{SERVER_URL}/get_api", json=payload, verify=server_transport_cert_path)
        if response.status_code != 200:
            assert False, f"/get_api failed with {response.status_code}"
        data = response.json()
        encrypted_api_key = data.get("api_key")
        api_key = pk.decrypt(b64d_url(encrypted_api_key), padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )).decode()

        # part 2
        timestamp = datetime.now(timezone.utc).isoformat()
        data_to_sign = f"{timestamp} - {api_key}".encode()

        signature = b64e_url(pk.sign(data_to_sign,
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
            assert False, f"/authenticate failed with {response.status_code}"
        data = response.json()
        return data['user_id'], api_key

def spoof_client_login(username, pk):
    # part 1
    payload = {
        "username": username
    }

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    response = requests.post(f"{SERVER_URL}/get_api", json=payload, verify=server_transport_cert_path)
    if response.status_code != 200:
        assert False, f"/get_api failed with {response.status_code}"
    data = response.json()
    encrypted_api_key = data.get("api_key")
    try:
        api_key = private_key.decrypt(b64d_url(encrypted_api_key), padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )).decode()
        assert False, f"API key decryption with diff. key not failed"
    except:
        pass

    api_key = pk.decrypt(b64d_url(encrypted_api_key), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )).decode()

    # part 2
    timestamp = datetime.now(timezone.utc).isoformat()
    data_to_sign = f"{timestamp} - {api_key}".encode()

    signature = b64e_url(private_key.sign(data_to_sign,
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
    assert response.status_code != 200,  "sign with different PK didn't fail"
    signature = b64e_url(pk.sign(data_to_sign,
                                          padding.PSS(
                                              mgf=padding.MGF1(hashes.SHA256()),
                                              salt_length=padding.PSS.MAX_LENGTH
                                          ),
                                          hashes.SHA256()))

    payload = {
        "timestamp": timestamp,
        "username": username + "_spoof",
        "api_key": api_key,
        "signature": signature
    }
    response = requests.post(f"{SERVER_URL}/authenticate", json=payload, verify=server_transport_cert_path)
    assert response.status_code != 200, "wrong username didn't fail"


def end_point_with_apikey(user_id):
    endpoint_list = [
        ("users", False),
        (f"users/{user_id}",False),
        (f"messages/{user_id}",False),
        ("logout",True),
        ("messages/send", True),
    ]
    test_api_key = base64.urlsafe_b64encode(os.urandom(16)).decode()
    headers = {
        "x-api-key": test_api_key
    }
    for endpoint, is_post in endpoint_list:
        if is_post:
            response = requests.post(f"{SERVER_URL}/{endpoint}", headers=headers, verify=server_transport_cert_path)
        else:
            response = requests.get(f"{SERVER_URL}/{endpoint}", headers=headers, verify=server_transport_cert_path)
        assert response.status_code != 200, f"Endpoint {endpoint} API KEY requirement failed."


    for endpoint, is_post in endpoint_list:
        if is_post:
            response = requests.post(f"{SERVER_URL}/{endpoint}", verify=server_transport_cert_path)
        else:
            response = requests.get(f"{SERVER_URL}/{endpoint}", verify=server_transport_cert_path)
        assert response.status_code != 200, f"Endpoint {endpoint} API KEY requirement failed."

def get_random_user(api_key, username=None):
    r = requests.get(f"{SERVER_URL}/users", headers={"x-api-key": api_key}, verify=server_transport_cert_path)
    if r.status_code != 200:
        assert False, f"/users failed with {r.status_code}"
    users = r.json()
    user = users[0]
    for u in users:
        if username is None:
            break
        if u["username"] == username:
            user = u
            break
    r = requests.get(f"{SERVER_URL}/users/{user['user_id']}", headers={"x-api-key": api_key}, verify=server_transport_cert_path)
    assert r.status_code == 200, f"/users/user_id failed with {r.status_code}"
    res = r.json()
    pem = r.json()["public_key_cert"].encode("utf-8")

    res['public_key_cert'] = x509.load_pem_x509_certificate(pem)
    return res

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

def rsa_encrypt_key(pub: RSAPublicKey, aes_key: bytes) -> bytes:
    return pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def send_invalid_signature_message(api_key, sender, recipient, sender_id, sender_pk, recipient_pk, recipient_id):
    message = "this is a message with an invalid signature"

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )


    ciphertext_blob, key = encrypt_chat_payload(sender, recipient, message, private_key)

    keys = [
                {
                    "encryption_key": b64e_url(rsa_encrypt_key(sender_pk.public_key(), key)),
                    "user_id": sender_id,
                },
                {
                    "encryption_key": b64e_url(rsa_encrypt_key(recipient_pk, key)),
                    "user_id": recipient_id,
                },
            ]
    payload = {
        "ciphertext": b64e_url(ciphertext_blob),
        "keys": keys,
        "recipient_id": recipient_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    r = requests.post(
        f"{SERVER_URL}/messages/send",
        json=payload,
        headers={"x-api-key": api_key},
        verify=server_transport_cert_path,
    )
    assert r.status_code == 200, f"/messages/send failed with {r.status_code}"

def load_pk(username):
    with open(privatekey_storage / f"{username}_private.pem", "rb") as key_file:
        private_key : RSAPrivateKey = serialization.load_pem_private_key(
            key_file.read(),
            password="password123".encode()  # or provide a password if the key is encrypted
        )
    return private_key

if __name__ == "__main__":
    # set values for your test
    username = "spoof"
    legit_username = "alice"
    # decide whether it's first try or not
    spoof_pk = generate_keypair(username)
    if spoof_pk is None:
        spoof_pk = load_pk(username)

    # test login endpoints
    spoof_client_login(username, spoof_pk)

    spoof_id, spoof_api =  legit_login(username, spoof_pk)

    # test api key endpoints
    end_point_with_apikey(spoof_id)
    # simulate invalid signature
    legit_user = get_random_user(spoof_api, legit_username)
    send_invalid_signature_message(spoof_api,username, legit_username, spoof_id, spoof_pk, legit_user["public_key_cert"].public_key(), legit_user["user_id"])
