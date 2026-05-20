from backend import db
from backend.utils import hash_password, verify_password, make_audit_record
from pymongo.errors import DuplicateKeyError

users = db['users']
audit = db['audit_logs']

# Ensure unique username index for authentication.
users.create_index('username', unique=True)

def register_user(username: str, password: str, email: str) -> dict:
    """Register a new military communication user with hashed password and email."""
    if users.find_one({'username': username}):
        return {'success': False, 'message': 'Username already exists'}
    credentials = hash_password(password)
    user_doc = {
        'username': username,
        'password_hash': credentials['hash'],
        'password_salt': credentials['salt'],
        'email': email,
        'role': 'user',
        'created_at': __import__('datetime').datetime.utcnow(),
        'failed_logins': 0,
        'lockout': False,
    }
    try:
        users.insert_one(user_doc)
        audit.insert_one(make_audit_record('register', username, 'User created successfully'))
        return {'success': True, 'message': 'Registration successful'}
    except DuplicateKeyError:
        return {'success': False, 'message': 'Username already exists'}

def authenticate_user(username: str, password: str, ip_address: str = None) -> dict:
    """Verify user credentials and record suspicious login activity."""
    user = users.find_one({'username': username})
    if not user:
        return None
    if user.get('lockout'):
        audit.insert_one(make_audit_record('login_attempt', username, 'Locked out user tried to login', ip_address))
        return None
    if verify_password(password, user['password_salt'], user['password_hash']):
        users.update_one({'username': username}, {'$set': {'failed_logins': 0}})
        audit.insert_one(make_audit_record('login', username, 'Successful login', ip_address))
        return user
    users.update_one({'username': username}, {'$inc': {'failed_logins': 1}})
    if user.get('failed_logins', 0) + 1 >= 5:
        users.update_one({'username': username}, {'$set': {'lockout': True}})
        audit.insert_one(make_audit_record('lockout', username, 'Account locked after failed logins', ip_address))
    else:
        audit.insert_one(make_audit_record('failed_login', username, 'Invalid credentials', ip_address))
    return None

def get_user_by_username(username: str) -> dict:
    return users.find_one({'username': username}, {'password_hash': 0, 'password_salt': 0})
