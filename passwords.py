import os
import base64
import getpass
import hashlib
import secrets
from cryptography.fernet import Fernet

# Generate or load a secret key
def generate_key(key_file="secret.key"):
    if not os.path.isfile(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as keyfile:
            keyfile.write(key)

    with open(key_file, "rb") as keyfile:
        return keyfile.read()

# Encrypt a password and return the ciphertext
def encrypt_password(key, password):
    cipher_suite = Fernet(key)
    ciphertext = cipher_suite.encrypt(password.encode())
    return base64.urlsafe_b64encode(ciphertext).decode()

# Decrypt a ciphertext and return the original password
def decrypt_password(key, ciphertext):
    cipher_suite = Fernet(key)
    ciphertext = base64.urlsafe_b64decode(ciphertext.encode())
    password = cipher_suite.decrypt(ciphertext).decode()
    return password

# Generate a secure random password
def generate_secure_password(length=16):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_"
    return ''.join(secrets.choice(chars) for _ in range(length))

# Create a salted hash of the master password
def create_hash(master_password, salt):
    hasher = hashlib.sha256()
    hasher.update(salt.encode())
    hasher.update(master_password.encode())
    return hasher.hexdigest()

# Verify the master password
def verify_master_password(stored_hash, input_password, salt):
    input_hash = create_hash(input_password, salt)
    return stored_hash == input_hash

# Main password manager function
def password_manager():
    print("Password Manager")

    key = generate_key()

    while True:
        print("\nOptions:")
        print("1. Store a new password")
        print("2. Retrieve a stored password")
        print("3. Change master password")
        print("4. Quit")
        choice = input("Select an option: ")

        if choice == "1":
            service = input("Enter the service or website name: ")
            username = input("Enter your username: )
            
            # Generate a secure random password
            password = generate_secure_password()
            encrypted_password = encrypt_password(key, password)

            with open("passwords.txt", "a") as password_file:
                password_file.write(f"{service} {username} {encrypted_password}\n")
            print(f"Generated and stored a secure password for {service}.")
        elif choice == "2":
            service = input("Enter the service or website name: ")
            username = input("Enter your username: ")

            found = False
            with open("passwords.txt", "r") as password_file:
                for line in password_file:
                    parts = line.split()
                    if len(parts) == 3 and parts[0] == service and parts[1] == username:
                        decrypted_password = decrypt_password(key, parts[2])
                        print(f"Password for {service}: {decrypted_password}")
                        found = True
                        break

            if not found:
                print("Password not found.")
        elif choice == "3":
            # Change master password
            new_master_password = getpass.getpass("Enter the new master password: ")
            salt = os.urandom(16)
            new_hash = create_hash(new_master_password, salt)
            with open("hash.txt", "w") as hash_file:
                hash_file.write(new_hash)
            print("Master password changed.")
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    # Check if the master password exists
    if not os.path.isfile("hash.txt"):
        master_password = getpass.getpass("Create a master password: ")
        salt = os.urandom(16)
        password_hash = create_hash(master_password, salt)
        with open("hash.txt", "w") as hash_file:
            hash_file.write(password_hash)

    # Verify the master password
    while True:
        input_password = getpass.getpass("Enter the master password: ")
        with open("hash.txt", "r") as hash_file:
            stored_hash = hash_file.read()
        if verify_master_password(stored_hash, input_password, salt.decode()):
            print("Access granted.")
            password_manager()
            break
        else:
            print("Access denied. Please try again.")
