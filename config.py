import os
from dotenv import load_dotenv

load_dotenv()

# Flask secret key for session encryption
SECRET_KEY = os.getenv('SECRET_KEY', 'military_secure_session_secret')

# MongoDB connection URI and database name
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
MONGO_DB = os.getenv('MONGO_DB', 'military_comm_system')

# Email alert settings for notification system
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USER = os.getenv('EMAIL_USER', 'alert@military-secure.com')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', 'change_this_password')

# AES encryption key salt and parameters
AES_KEY_SIZE = 32
AES_BLOCK_SIZE = 16

# Threat detection model path
THREAT_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'data', 'threat_model.joblib')
