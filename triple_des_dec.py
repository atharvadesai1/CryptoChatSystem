from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

def triple_des_decrypt(ciphertext, key):
    # Ensure the key is 24 bytes long (3 * 8 bytes)
    key = key[:24].ljust(24, b'\0')

    # Initialize the 3DES cipher with CBC mode
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(b'\0' * 8), backend=default_backend())

    # Create an unpadder for PKCS7 padding
    unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()

    # Decode the base64-encoded ciphertext
    ciphertext_bytes = base64.b64decode(ciphertext)

    # Create a decryptor object
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_data = decryptor.update(ciphertext_bytes) + decryptor.finalize()

    # Remove padding
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

    # Decode the plaintext from bytes to string
    plaintext_str = plaintext.decode('utf-8')

    return plaintext_str

# Example usage
ciphertext = "miaILw9T9R+rPDTNMei/Pg=="
key = b"mysecretkeymysecretkeymysecretkey"  # 24 bytes key

plaintext = triple_des_decrypt(ciphertext, key)
print("Ciphertext:", ciphertext)
print("Plaintext:", plaintext)
