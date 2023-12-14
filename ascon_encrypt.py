import ascon
import json
import secrets

def encrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Generate a random nonce
    nonce = secrets.token_bytes(16)

    # Optionally provide associated data
    associated_data = b"Associated Data"

    # Perform encryption
    ciphertext = ascon.encrypt(key, nonce, associated_data, plaintext)

    with open(output_file, 'wb') as f:
        f.write(nonce)
        f.write(ciphertext)

def generate_key():
    # Generate a 128-bit (16-byte) key using secrets module
    return secrets.token_bytes(16)

def save_key_to_json(filename, key):
    key_hex = key.hex()
    key_data = {'key': key_hex}
    with open(filename, 'w') as f:
        json.dump(key_data, f)

if __name__ == "__main__":
    key = generate_key()

    # Save the key to a JSON file
    save_key_to_json('private_key.json', key)

    data_to_encrypt = b"Hello, World!"
    input_file = 'plaintext.txt'
    encrypted_file = 'encrypted_file.bin'

    encrypt_file(input_file, encrypted_file, key)
