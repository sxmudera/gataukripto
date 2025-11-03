from PIL import Image

def _to_bits(data: bytes):
    for byte in data:
        for i in range(8)[::-1]:
            yield (byte >> i) & 1

def embed_text_in_image(in_image_path: str, out_image_path: str, secret_text: str):
    img = Image.open(in_image_path)
    img = img.convert('RGB')
    width, height = img.size
    pixels = img.load()

    data = secret_text.encode('utf-8')
    length = len(data)
    max_bytes = (width * height * 3) // 8 - 4
    if length > max_bytes:
        raise ValueError('Message too large to embed')

    payload = length.to_bytes(4, 'big') + data
    bits = list(_to_bits(payload))

    bit_idx = 0
    for y in range(height):
        for x in range(width):
            if bit_idx >= len(bits):
                break
            r, g, b = pixels[x, y]
            r = (r & ~1) | bits[bit_idx]; bit_idx += 1
            if bit_idx < len(bits):
                g = (g & ~1) | bits[bit_idx]; bit_idx += 1
            if bit_idx < len(bits):
                b = (b & ~1) | bits[bit_idx]; bit_idx += 1
            pixels[x, y] = (r, g, b)
        if bit_idx >= len(bits):
            break

    img.save(out_image_path)

def extract_text_from_image(image_path: str) -> str:
    img = Image.open(image_path).convert('RGB')
    width, height = img.size
    pixels = img.load()
    bits = []
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            bits.append(r & 1)
            bits.append(g & 1)
            bits.append(b & 1)
    length_bits = bits[:32]
    length = 0
    for b in length_bits:
        length = (length << 1) | b
    total_bytes = length
    data_bits = bits[32:32 + total_bytes * 8]
    out = bytearray()
    for i in range(0, len(data_bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | data_bits[i + j]
        out.append(byte)
    return out.decode('utf-8')
