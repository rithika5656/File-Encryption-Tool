"""
File encryption and decryption module using Fernet (symmetric encryption)
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64
import os


def generate_key_from_password(password: str, salt: bytes = None) -> tuple:
    """
    Generate encryption key from password using PBKDF2
    
    Args:
        password: Password string to derive key from
        salt: Optional salt bytes (generated if not provided)
    
    Returns:
        Tuple of (key, salt)
    """
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def encrypt_file(file_path: str, password: str) -> str:
    """
    Encrypt a file using password-based encryption
    
    Args:
        file_path: Path to the file to encrypt
        password: Password for encryption
    
    Returns:
        Path to encrypted file
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Generate key from password
    key, salt = generate_key_from_password(password)
    cipher = Fernet(key)
    
    # Read original file
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    # Encrypt the data
    encrypted_data = cipher.encrypt(file_data)
    
    # Write encrypted file with salt prepended
    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + encrypted_data)
    
    print(f"✓ File encrypted successfully: {encrypted_file_path}")
    return encrypted_file_path


def decrypt_file(encrypted_file_path: str, password: str, output_path: str = None) -> str:
    """
    Decrypt an encrypted file using password
    
    Args:
        encrypted_file_path: Path to the encrypted file
        password: Password for decryption
        output_path: Optional custom output path (defaults to removing .encrypted)
    
    Returns:
        Path to decrypted file
    """
    if not os.path.exists(encrypted_file_path):
        raise FileNotFoundError(f"File not found: {encrypted_file_path}")
    
    # Read encrypted file
    with open(encrypted_file_path, 'rb') as f:
        salt = f.read(16)  # First 16 bytes are salt
        encrypted_data = f.read()
    
    # Generate key from password using the same salt
    key, _ = generate_key_from_password(password, salt)
    cipher = Fernet(key)
    
    try:
        # Decrypt the data
        decrypted_data = cipher.decrypt(encrypted_data)
    except Exception as e:
        raise ValueError("Decryption failed. Incorrect password or corrupted file.") from e
    
    # Determine output path
    if output_path is None:
        if encrypted_file_path.endswith('.encrypted'):
            output_path = encrypted_file_path[:-10]  # Remove .encrypted extension
        else:
            output_path = encrypted_file_path + '.decrypted'
    
    # Write decrypted file
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"✓ File decrypted successfully: {output_path}")
    return output_path
