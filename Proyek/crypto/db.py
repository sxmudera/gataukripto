import mysql.connector
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from config import MASTER_KEY
import base64

def get_db():
    """Membuka koneksi ke database MySQL"""
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )

def execute_query(query, params=None):
    """Menjalankan INSERT/UPDATE/DELETE"""
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute(query, params or ())
    conn.commit()
    cur.close()
    conn.close()

def fetch_query(query, params=None, one=False):
    """Menjalankan SELECT"""
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute(query, params or ())
    result = cur.fetchone() if one else cur.fetchall()
    cur.close()
    conn.close()
    return result

AES_KEY = MASTER_KEY  # must be 16/24/32 bytes; here assumed 32 bytes

def aes_encrypt(plaintext: bytes) -> str:
    """AES-CCM: returns base64(nonce|tag|ciphertext)"""
    nonce = get_random_bytes(11)  # CCM nonce: 7-13 bytes
    cipher = AES.new(AES_KEY, AES.MODE_CCM, nonce=nonce)
    ct = cipher.encrypt(plaintext)
    tag = cipher.digest()  # 16-byte default
    payload = nonce + tag + ct
    return base64.b64encode(payload).decode('utf-8')

def aes_decrypt(b64payload: str) -> bytes:
    payload = base64.b64decode(b64payload)
    nonce = payload[:11]
    tag = payload[11:27]
    ct = payload[27:]
    cipher = AES.new(AES_KEY, AES.MODE_CCM, nonce=nonce)
    cipher.update(b"")  # optional, can authenticate additional data
    return cipher.decrypt_and_verify(ct, tag)
