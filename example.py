"""
Example usage of the File Encryption Tool
"""

from encryption import encrypt_file, decrypt_file

# Example: Encrypt a file
print("=== File Encryption Tool Demo ===\n")

# Create a sample file
sample_file = "sample.txt"
with open(sample_file, 'w') as f:
    f.write("This is a secret message that needs to be encrypted!")

print("1. Original file created: sample.txt")

# Encrypt the file
password = "my_secret_password"
encrypted_file = encrypt_file(sample_file, password)
print(f"2. Encrypted file created: {encrypted_file}")

# Decrypt the file
decrypted_file = decrypt_file(encrypted_file, password, "sample_decrypted.txt")
print(f"3. Decrypted file created: {decrypted_file}")

# Verify the decrypted content
with open(decrypted_file, 'r') as f:
    print(f"\n4. Decrypted content: {f.read()}")
