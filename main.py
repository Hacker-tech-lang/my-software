import os
import base64
import hashlib
from cryptography.fernet import Fernet
from getpass import getpass

# File to store the encrypted passwords
PASSWORDS_FILE = "passwords.txt"

# Function to generate and store encryption key
def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
    return key

# Function to load the encryption key from a file
def load_key():
    return open("key.key", "rb").read()

# Initialize key
if not os.path.exists("key.key"):
    key = generate_key()
else:
    key = load_key()

fernet = Fernet(key)

# Function to encrypt and store the password
def save_password(service, password):
    encrypted_password = fernet.encrypt(password.encode())
    with open(PASSWORDS_FILE, "a") as f:
        f.write(f"{service}:{encrypted_password.decode()}\n")

# Function to retrieve and decrypt the password
def get_password(service):
    if not os.path.exists(PASSWORDS_FILE):
        print("No passwords stored yet.")
        return
    with open(PASSWORDS_FILE, "r") as f:
        for line in f.readlines():
            stored_service, stored_encrypted_password = line.strip().split(":")
            if stored_service == service:
                decrypted_password = fernet.decrypt(stored_encrypted_password.encode()).decode()
                return decrypted_password
    print("Service not found.")
    return None

# Main program loop
def main():
    print("Welcome to the Secure Password Manager!")
    while True:
        print("\nOptions:")
        print("1. Save a password")
        print("2. Retrieve a password")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == "1":
            service = input("Enter the name of the service: ")
            password = getpass("Enter the password: ")
            save_password(service, password)
            print(f"Password for {service} saved securely!")
        elif choice == "2":
            service = input("Enter the name of the service: ")
            password = get_password(service)
            if password:
                print(f"Password for {service}: {password}")
        elif choice == "3":
            print("Exiting password manager.")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
          
