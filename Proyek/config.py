import os

FLASK_SECRET = os.environ.get('FLASK_SECRET', 'devsecret')
MASTER_KEY = bytes.fromhex(os.environ.get('MASTER_KEY_HEX', '0'*64))

ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 102400
ARGON2_PARALLELISM = 8

UPLOAD_FOLDER = 'static/uploads'
ENCRYPTED_FILES_FOLDER = os.path.join(UPLOAD_FOLDER, 'encrypted_files')
STEGO_FOLDER = os.path.join(UPLOAD_FOLDER, 'stego_images')

DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_USER = os.environ.get('DB_USER', 'root')
DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
DB_NAME = os.environ.get('DB_NAME', 'secure_mail')

