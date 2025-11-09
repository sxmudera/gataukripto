from argon2 import PasswordHasher
from config import ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM

ph = PasswordHasher(time_cost=ARGON2_TIME_COST, memory_cost=ARGON2_MEMORY_COST, parallelism=ARGON2_PARALLELISM)

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(hash_pw: str, password: str) -> bool:
    try:
        return ph.verify(hash_pw, password)
    except Exception:
        return False
