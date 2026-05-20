from backend import db
from backend.encryption import encrypt_message
from backend.utils import make_audit_record

messages = db['messages']
audit = db['audit_logs']

# Save encrypted communication between sender and recipient and keep message history.
def save_encrypted_message(sender: str, recipient: str, encrypted_payload: dict, subject: str = None, priority: str = 'normal') -> str:
    storage = {
        'sender': sender,
        'recipient': recipient,
        'cipher_text': encrypted_payload['cipher_text'],
        'algorithm': encrypted_payload['algorithm'],
        'subject': subject or 'No subject',
        'priority': priority,
        'created_at': __import__('datetime').datetime.utcnow(),
        'status': 'encrypted',
    }
    result = messages.insert_one(storage)
    audit.insert_one(make_audit_record('send_message', sender, f'Message sent to {recipient} with priority {priority}', None))
    return str(result.inserted_id)

# Retrieve the encrypted conversation history for a pair of users.
def get_conversation(user_a: str, user_b: str) -> list:
    query = {'$or': [
        {'sender': user_a, 'recipient': user_b},
        {'sender': user_b, 'recipient': user_a}
    ]}
    conversation = list(messages.find(query, {'_id': 0}).sort('created_at', 1))
    return conversation

# Transfer logic that optionally can create messages from plain text using AES encryption.
def create_and_send(sender: str, recipient: str, plain_text: str) -> dict:
    encrypted_payload = encrypt_message(plain_text)
    message_id = save_encrypted_message(sender, recipient, encrypted_payload)
    return {'message_id': message_id, 'encrypted_payload': encrypted_payload}
