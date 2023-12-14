import ascon
import json

def decrypt_file(encrypted_file, output_file, key):
    with open(encrypted_file, 'rb') as f:
        nonce = f.read(16)  # Read the nonce from the file
        ciphertext = f.read()

    # Optionally provide associated data
    associated_data = b"Associated Data"

    try:
        # Perform decryption
        plaintext = ascon.decrypt(key, nonce, associated_data, ciphertext)

        with open(output_file, 'wb') as f:
            f.write(plaintext)

        print("Decryption successful.")
    except Exception as e:
        print(f"Decryption failed: {e}")

def load_key_from_json(filename):
    with open(filename, 'r') as f:
        key_data = json.load(f)

    key_hex = key_data['key']
    key_bytes = bytes.fromhex(key_hex)

    return key_bytes

if __name__ == "__main__":
    # Read key from JSON file
    private_key_filename = 'private_key.json'
    key = load_key_from_json(private_key_filename)

    # Decryption
    encrypted_file = 'encrypted_file.bin'
    decrypted_file = 'decrypted_file.txt'

    decrypt_file(encrypted_file, decrypted_file, key)
