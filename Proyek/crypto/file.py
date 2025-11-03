from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad

def encrypt_file(input_file, output_file, key):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    with open(input_file, 'rb') as f:
        data = f.read()
    padded_data = pad(data, Blowfish.block_size)
    encrypted = cipher.iv + cipher.encrypt(padded_data)
    with open(output_file, 'wb') as f:
        f.write(encrypted)

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        iv = f.read(8)
        data = f.read()
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(data), Blowfish.block_size)
    with open(output_file, 'wb') as f:
        f.write(decrypted)
