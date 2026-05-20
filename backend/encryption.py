from backend.utils import generate_aes_key, encode_key, decode_key, aes_encrypt, aes_decrypt
from backend import db
import base64

message_keys = db['message_keys']
messages = db['messages']

# For this prototype, a shared system master key is generated once and cached in database.
MASTER_KEY_NAME = 'system_aes_master_key'

def get_system_key() -> bytes:
    record = message_keys.find_one({'name': MASTER_KEY_NAME})
    if record:
        return decode_key(record['key'])
    key = generate_aes_key()
    message_keys.insert_one({'name': MASTER_KEY_NAME, 'key': encode_key(key)})
    return key

# Encrypt a plain text message using AES and include metadata for decryption.
def encrypt_message(plain_text: str) -> dict:
    key = get_system_key()
    cipher_text = aes_encrypt(plain_text, key)
    return {
        'cipher_text': cipher_text,
        'key_info': 'system-master-key-v1',
        'algorithm': 'AES-CBC-256',
    }

# Decrypt a stored cipher text using the system AES key.
def decrypt_message(cipher_text: str) -> str:
    key = get_system_key()
    return aes_decrypt(cipher_text, key)

# Securely store audit metadata for encrypted message events.
def log_encryption_event(sender: str, recipient: str, message_id: str):
    db['audit_logs'].insert_one({
        'timestamp': __import__('datetime').datetime.utcnow(),
        'action': 'message_encrypted',
        'sender': sender,
        'recipient': recipient,
        'message_id': message_id,
    })
