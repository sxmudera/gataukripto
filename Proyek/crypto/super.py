# super.py
def atbash_bytes(data: bytes) -> bytes:
    """
    Atbash cipher on ASCII letters (A-Z, a-z) in bytes.
    Non-letters are unchanged.
    """
    result = bytearray()
    for b in data:
        if 65 <= b <= 90:
            result.append(65 + (25 - (b - 65)))
        elif 97 <= b <= 122:
            result.append(97 + (25 - (b - 97)))
        else:
            result.append(b)
    return bytes(result)

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """
    XOR each byte with repeating key bytes
    """
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def super_encrypt(plaintext: str, xor_key: str = 'key') -> bytes:
    """
    plaintext: str -> bytes
    returns bytes
    """
    step1 = atbash_bytes(plaintext.encode('utf-8'))
    step2 = xor_bytes(step1, xor_key.encode('utf-8'))
    return step2

def super_decrypt(cipherbytes: bytes, xor_key: str = 'key') -> str:
    """
    cipherbytes: bytes -> plaintext str
    """
    step1 = xor_bytes(cipherbytes, xor_key.encode('utf-8'))
    step2 = atbash_bytes(step1)
    return step2.decode('utf-8', errors='replace')

