import ascon

def decrypt_file(encrypted_file, output_file, key):
    with open(encrypted_file, 'rb') as f:
        nonce = f.read(16)  # Read the nonce from the file
        ciphertext = f.read()

    # Optionally provide associated data
    associated_data = b"Associated Data"

    # Perform decryption
    plaintext = ascon.decrypt(key, nonce, associated_data, ciphertext)

    with open(output_file, 'wb') as f:
        f.write(plaintext)

if __name__ == "__main__":
    key = b'Sixteen byte key'
    encrypted_file = 'encrypted_file.bin'
    decrypted_file = 'decrypted_file.txt'

    decrypt_file(encrypted_file, decrypted_file, key)
