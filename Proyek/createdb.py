from mysql.connector import connect,Error
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from crypto.db import execute_query

def create_database():
    """Membuat database jika belum ada"""
    try:
        conn = connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cur = conn.cursor()
        cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
        print(f"Database '{DB_NAME}' created/checked successfully.")
        cur.close()
        conn.close()
    except Error as e:
        print("Database creation error:", e)

def init_db():
    try:
        execute_query("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(150) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
        execute_query("""
            CREATE TABLE IF NOT EXISTS messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender VARCHAR(150) NOT NULL,
                recipient VARCHAR(150) NOT NULL,
                type ENUM('text','image','file') NOT NULL,
                payload LONGTEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    except Error as e:
        print("DB init error:", e)