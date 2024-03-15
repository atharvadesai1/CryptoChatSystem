from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

def triple_des_decrypt(ciphertext, key):
    key = key[:24].ljust(24, b'\0')
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(b'\0' * 8), backend=default_backend())
    unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
    ciphertext_bytes = base64.b64decode(ciphertext)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext_bytes) + decryptor.finalize()

    # Remove padding
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

    # Decode the plaintext from bytes to string
    plaintext_str = plaintext.decode('utf-8')

    return plaintext_str

# Example usage
ciphertext = "AodmHI/nKpgp1svTt5b0cg=="
key = b"random"  # 24 bytes key

plaintext = triple_des_decrypt(ciphertext, key)
print("Ciphertext:", ciphertext)
print("Plaintext:", plaintext)