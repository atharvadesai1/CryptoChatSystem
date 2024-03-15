from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from flask_cors import CORS
import base64

app = Flask(__name__)
CORS(app)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    plaintext = data.get('plaintext')
    key = data.get('key')
    # Ensure the key is 24 bytes long (3 * 8 bytes)
    key = key.ljust(24, '\0')
    # Initialize the 3DES cipher with CBC mode
    cipher = Cipher(algorithms.TripleDES(key.encode()), modes.CBC(b'\0' * 8), backend=default_backend())
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
    return jsonify({'ciphertext': encoded_ciphertext})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    ciphertext = base64.b64decode(data.get('ciphertext').encode('utf-8'))
    key = data.get('key')
    # Ensure the key is 24 bytes long (3 * 8 bytes)
    key = key.ljust(24, '\0')
    # Initialize the 3DES cipher with CBC mode
    cipher = Cipher(algorithms.TripleDES(key.encode()), modes.CBC(b'\0' * 8), backend=default_backend())
    # Create a decryptor object
    decryptor = cipher.decryptor()
    # Decrypt the ciphertext
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    # Create an unpadder for PKCS7 padding
    unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
    # Remove padding from the decrypted data
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return jsonify({'plaintext': plaintext.decode('utf-8')})

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
