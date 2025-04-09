import os
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# 🔑 Convert password to secure encryption key using salt
def password_to_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# 🔐 Encrypt a file with the password
def encrypt_file(file_path, password):
    salt = os.urandom(16)  # random salt
    key = password_to_key(password, salt)
    fernet = Fernet(key)

    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        encrypted = fernet.encrypt(data)

        with open(file_path + ".enc", 'wb') as f:
            f.write(salt + encrypted)  # prepend salt to encrypted data

        print(f"[+] File encrypted: {file_path}.enc")
    except Exception as e:
        print(f"[-] Encryption failed: {str(e)}")

# 🔓 Decrypt a file with the password
def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()

        salt = content[:16]  # extract the salt
        encrypted_data = content[16:]

        key = password_to_key(password, salt)
        fernet = Fernet(key)

        decrypted = fernet.decrypt(encrypted_data)

        output_path = file_path.replace(".enc", ".dec")
        with open(output_path, 'wb') as f:
            f.write(decrypted)

        print(f"[+] File decrypted: {output_path}")
    except Exception as e:
        print("[-] Incorrect password or corrupted file.")
        print(f"Error: {str(e)}")

# 🚀 Main program
if __name__ == "__main__":
    print("=== 🔐 Password-Protected File Locker ===")
    action = input("Do you want to (E)ncrypt or (D)ecrypt? ").strip().lower()
    file_path = input("Enter file path (e.g., example.txt): ").strip()

    if not os.path.exists(file_path):
        print("[-] File does not exist.")
        exit()

    password = getpass.getpass("Enter password: ")

    if action == 'e':
        encrypt_file(file_path, password)
    elif action == 'd':
        decrypt_file(file_path, password)
    else:
        print("[-] Invalid choice. Please enter E or D.")
