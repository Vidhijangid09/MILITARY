from pymongo import MongoClient, errors
import config

# Initialize a MongoDB client and default database connection.
# If a real MongoDB server is not available, fall back to an in-memory mongomock client
try:
	client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=5000)
	# Force a server selection to detect connection issues early
	client.server_info()
	db = client[config.MONGO_DB]
except Exception:
	try:
		import mongomock
		client = mongomock.MongoClient()
		db = client[config.MONGO_DB]
		print('Warning: MongoDB not available. Using in-memory mongomock database.')
	except Exception:
		raise

# Expose backend submodules for convenient imports.
from backend import auth, encryption, threat_detection, communication, dashboard, utils
