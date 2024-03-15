from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

def triple_des_encrypt(plaintext, key):
    # Ensure the key is 24 bytes long (3 * 8 bytes)
    key = key[:24].ljust(24, b'\0')

    # Initialize the 3DES cipher with CBC mode
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(b'\0' * 8), backend=default_backend())

    # Create a padder for PKCS7 padding
    padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()

    # Apply padding to the plaintext
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    # Create an encryptor object
    encryptor = cipher.encryptor()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Encode the ciphertext in base64 for easy representation
    encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')

    return encoded_ciphertext

# Example usage   
plaintext = "Welcome to my world"
key = b"mysecretkeymysecretkeymysecretkey"  # 24 bytes key

ciphertext = triple_des_encrypt(plaintext, key)
print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext)
