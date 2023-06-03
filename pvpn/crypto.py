from Crypto.Cipher import ChaCha20_Poly1305

def aead_chacha20poly1305_encrypt(key: bytes, counter: int, plain_text: bytes, auth_text: bytes) -> bytes:
    cipher = ChaCha20_Poly1305.new(key=key, nonce=b'\x00\x00\x00\x00'+counter.to_bytes(8, 'little'))
    cipher.update(auth_text)
    cipher_text, digest = cipher.encrypt_and_digest(plain_text)
    return cipher_text+digest

def aead_chacha20poly1305_decrypt(key: bytes, counter: int, cipher_text: bytes, auth_text: bytes) -> bytes:
    cipher = ChaCha20_Poly1305.new(key=key, nonce=b'\x00\x00\x00\x00'+counter.to_bytes(8, 'little'))
    cipher.update(auth_text)
    return cipher.decrypt_and_verify(cipher_text[:-16], cipher_text[-16:])

def ec_scalar(k: int, u: int, p: int, a24: int, bits: int) -> int:
    x_2, x_3, z_2, z_3, swap = 1, u, 0, 1, 0
    for t in range(bits-1, -1, -1):
        k_t = (k >> t) & 1
        if swap^k_t:
            x_2, x_3, z_2, z_3 = x_3, x_2, z_3, z_2
        swap = k_t
        A, B, C, D = x_2+z_2, x_2-z_2, x_3+z_3, x_3-z_3
        AA, BB, DA, CB = A*A, B*B, D*A, C*B
        E   = AA - BB
        x_3 = pow(DA + CB, 2, p)
        z_3 = u * pow(DA - CB, 2, p) % p
        x_2 = AA * BB % p
        z_2 = E * (AA + a24*E) % p
    if swap:
        x_2, x_3, z_2, z_3 = x_3, x_2, z_3, z_2
    return (x_2 * pow(z_2, p-2, p) % p)

def X25519(k: bytes, u: int | bytes) -> bytes:
    u1, k1 = int.from_bytes(u, 'little') if isinstance(u, bytes) else u, int.from_bytes(k, 'little')
    k1 = k1 & ((1 << 256) - (1 << 255) - 8) | (1 << 254)
    return ec_scalar(k1, u1, 2**255-19, 121665, 255).to_bytes(32, 'little')
