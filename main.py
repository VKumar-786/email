from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib, hmac, base64

app = FastAPI()

def kyber_encapsulate():
    shared_key = get_random_bytes(32)
    encrypted_key = base64.b64encode(shared_key).decode()
    return encrypted_key, shared_key

def kyber_decapsulate(encrypted_key: str):
    try:
        return base64.b64decode(encrypted_key)
    except:
        raise HTTPException(status_code=400, detail="Invalid encrypted key")

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode()
    }

def aes_decrypt(enc_data, nonce, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=base64.b64decode(nonce))
    return cipher.decrypt(base64.b64decode(enc_data)).decode()

def generate_mac(data, key):
    return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()

class EncryptRequest(BaseModel):
    message: str

class DecryptRequest(BaseModel):
    encrypted_key: str
    ciphertext: str
    nonce: str
    tag: str

@app.post("/encrypt")
def encrypt(req: EncryptRequest):
    encrypted_key, shared_key = kyber_encapsulate()
    encrypted = aes_encrypt(req.message, shared_key)
    tag = generate_mac(encrypted["ciphertext"] + encrypted_key, shared_key)
    return {
        "encrypted_key": encrypted_key,
        "ciphertext": encrypted["ciphertext"],
        "nonce": encrypted["nonce"],
        "tag": tag
    }

@app.post("/decrypt")
def decrypt(req: DecryptRequest):
    shared_key = kyber_decapsulate(req.encrypted_key)
    expected_tag = generate_mac(req.ciphertext + req.encrypted_key, shared_key)
    if not hmac.compare_digest(expected_tag, req.tag):
        raise HTTPException(status_code=403, detail="Tag mismatch")
    plain = aes_decrypt(req.ciphertext, req.nonce, shared_key)
    return {"message": plain}
