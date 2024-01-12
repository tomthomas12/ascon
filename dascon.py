import ascon
import json
import hashlib

def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()

    with open(file_path, 'rb') as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()

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

def verify_hash_from_json(filename, expected_hash):
    with open(filename, 'r') as f:
        hash_data = json.load(f)

    hash_value = hash_data.get('hash_value', None)

    if hash_value is not None and hash_value == expected_hash:
        print("Hash verification successful.")
        return True
    else:
        print("Hash verification failed.")
        return False

if __name__ == "__main__":
    # Read key from JSON file
    private_key_filename = 'private_key.json'
    key = load_key_from_json(private_key_filename)

    # Decryption
    encrypted_file = 'encrypted_file.bin'
    decrypted_file = 'decrypted_file.txt'
    print("")
    decrypt_file(encrypted_file, decrypted_file, key)
    expected_hash = calculate_hash(decrypted_file)

    if verify_hash_from_json('hash_value.json', expected_hash):
        print("")
