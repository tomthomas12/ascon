from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes
import ascon
import secrets

def generate_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(private_key, data):
    signature = private_key.sign(data)
    return signature

def encrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Generate a nonce
    nonce = secrets.token_bytes(16)  # 16 bytes for Ascon-128

    # Optionally provide associated data
    associated_data = b"Associated Data"

    # Perform encryption
    ciphertext = ascon.encrypt(key, nonce, associated_data, plaintext)

    with open(output_file, 'wb') as f:
        f.write(nonce)
        f.write(ciphertext)

if __name__ == "__main__":
    private_key, public_key = generate_keypair()
    data_to_encrypt = b"Hello, World!"
    
    # Sign the data
    signature = sign_data(private_key, data_to_encrypt)
    
    # Encryption
    key = b'Sixteen byte key'
    input_file = r'C:\Users\tom\hello\demo.txt'  # Use a raw string to handle backslashes
    encrypted_file = 'encrypted_file.bin'
    
    # Combine data and signature for secure storage
    data_to_encrypt_with_signature = data_to_encrypt + signature
    
    encrypt_file(input_file, encrypted_file, key)
