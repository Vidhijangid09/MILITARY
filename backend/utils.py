import hashlib
import os
import binascii
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Hash a plain password using SHA-256 and a salt for safe storage.
def hash_password(password: str, salt: bytes = None) -> dict:
    if salt is None:
        salt = os.urandom(16)
    password_bytes = password.encode('utf-8')
    hashed = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000)
    return {'salt': binascii.hexlify(salt).decode('utf-8'), 'hash': binascii.hexlify(hashed).decode('utf-8')}

# Verify a password against stored hash and salt.
def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    salt = binascii.unhexlify(salt_hex)
    candidate = hash_password(password, salt)
    return candidate['hash'] == hash_hex

# Create a secure random AES key for message encryption.
def generate_aes_key(length: int = 32) -> bytes:
    return get_random_bytes(length)

# Convert a raw AES key to a base64-safe string for transport/storage.
def encode_key(key: bytes) -> str:
    return base64.b64encode(key).decode('utf-8')

# Convert the base64-safe string back to raw AES bytes.
def decode_key(key_str: str) -> bytes:
    return base64.b64decode(key_str.encode('utf-8'))

# Generate a secure initialization vector for AES encryption.
def generate_iv() -> bytes:
    return get_random_bytes(AES.block_size)

# AES encrypt plain text using CBC mode with PKCS7 padding.
def aes_encrypt(plain_text: str, key: bytes) -> str:
    iv = generate_iv()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
    encrypted_payload = iv + encrypted_bytes
    return base64.b64encode(encrypted_payload).decode('utf-8')

# AES decrypt base64 encoded cipher text using the provided key.
def aes_decrypt(cipher_text: str, key: bytes) -> str:
    encrypted_payload = base64.b64decode(cipher_text)
    iv = encrypted_payload[:AES.block_size]
    cipher_bytes = encrypted_payload[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_bytes = unpad(cipher.decrypt(cipher_bytes), AES.block_size)
    return plain_bytes.decode('utf-8')

# Format an audit log entry for the system.
def make_audit_record(action: str, username: str, details: str, ip_address: str = None) -> dict:
    record = {
        'timestamp': __import__('datetime').datetime.utcnow().isoformat() + 'Z',
        'action': action,
        'username': username,
        'details': details,
        'ip_address': ip_address,
    }
    return record
