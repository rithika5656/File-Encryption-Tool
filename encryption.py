"""
File encryption and decryption module using Fernet (symmetric encryption).
"""

import base64
import os
import logging
import secrets
from pathlib import Path
from typing import Tuple, Optional, Callable, Union

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.exceptions import InvalidKey

# Constants
ITERATIONS: int = 600_000  # OWASP recommended for PBKDF2-HMAC-SHA256
SALT_SIZE: int = 16
CHUNK_SIZE: int = 64 * 1024  # 64KB chunks
LARGE_FILE_THRESHOLD: int = 500 * 1024 * 1024  # 500MB

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class EncryptionError(Exception):
    """Base exception for encryption/decryption errors."""
    pass

class DecryptionError(EncryptionError):
    """Raised when decryption fails (bad password or corrupted file)."""
    pass

def generate_key_from_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Generates an encryption key from a password using PBKDF2.

    Args:
        password: The password string to derive the key from.
        salt: Optional salt bytes. If not provided, a random salt is generated.

    Returns:
        A tuple containing (key_bytes, salt_bytes).

    Raises:
        ValueError: If the password is empty.
    """
    if not password:
        raise ValueError("Password cannot be empty")
        
    if salt is None:
        # Use secrets for cryptographically strong random numbers
        salt = secrets.token_bytes(SALT_SIZE)
    
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_file(
    file_path: Union[str, Path], 
    password: str, 
    callback: Optional[Callable[[int, int], None]] = None
) -> Path:
    """Encrypts a file using password-based encryption.

    Args:
        file_path: Path to the file to encrypt.
        password: The password to use for encryption.
        callback: Optional function(current_bytes, total_bytes) to report progress.

    Returns:
        The Path to the encrypted file.

    Raises:
        FileNotFoundError: If the input file does not exist.
        EncryptionError: If the encryption process fails.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
        
    logger.info(f"Starting encryption for {path}")
    
    try:
        # Check file size warning
        file_size = path.stat().st_size
        if file_size > LARGE_FILE_THRESHOLD:
            logger.warning(f"File {path.name} is large ({file_size / 1024 / 1024:.2f} MB). High memory usage expected.")

        # Generate key
        key, salt = generate_key_from_password(password)
        cipher = Fernet(key)
        
        # Prepare output path
        output_path = path.with_suffix(path.suffix + '.encrypted')
        
        # Read all data (Fernet standard limitation)
        with open(path, 'rb') as infile:
            file_data = infile.read()
            
        encrypted_data = cipher.encrypt(file_data)
        
        with open(output_path, 'wb') as outfile:
            outfile.write(salt)
            outfile.write(encrypted_data)
            
        if callback:
            callback(len(file_data), len(file_data))
                
        logger.info(f"Encrypted {path} -> {output_path}")
        return output_path
        
    except Exception as e:
        # Clean up partial file if exists
        if 'output_path' in locals() and output_path.exists():
            output_path.unlink()
        raise EncryptionError(f"Encryption failed: {e}") from e

def decrypt_file(
    encrypted_path: Union[str, Path], 
    password: str, 
    output_path: Optional[Union[str, Path]] = None,
    callback: Optional[Callable[[int, int], None]] = None
) -> Path:
    """Decrypts an encrypted file.

    Args:
        encrypted_path: Path to the encrypted file.
        password: The password to use for decryption.
        output_path: Optional custom path for the decrypted file.
        callback: Optional function(current_bytes, total_bytes) to report progress.

    Returns:
        The Path to the decrypted file.

    Raises:
        FileNotFoundError: If the input file does not exist.
        DecryptionError: If decryption fails (wrong password or corruption).
    """
    path = Path(encrypted_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
        
    logger.info(f"Starting decryption for {path}")

    try:
        with open(path, 'rb') as f:
            # Read salt
            salt = f.read(SALT_SIZE)
            if len(salt) != SALT_SIZE:
                raise DecryptionError("File is too short to contain a valid salt.")
                
            # Read encrypted data
            encrypted_data = f.read()
            
        # Derive key
        key, _ = generate_key_from_password(password, salt)
        cipher = Fernet(key)
        
        try:
            decrypted_data = cipher.decrypt(encrypted_data)
        except InvalidKey:
             raise DecryptionError("Incorrect password or corrupted data.")
        except Exception as e:
             raise DecryptionError(f"Decryption failed: {str(e)}") from e
             
        # Determine output path
        if output_path is None:
            if path.suffix == '.encrypted':
                output_path = path.with_suffix('')
            else:
                output_path = path.with_suffix(path.suffix + '.decrypted')
        
        out_path_obj = Path(output_path)
        
        # Write decrypted data
        with open(out_path_obj, 'wb') as f:
            f.write(decrypted_data)
            
        if callback:
             callback(len(decrypted_data), len(decrypted_data))
             
        logger.info(f"Decrypted {path} -> {out_path_obj}")
        return out_path_obj
        
    except Exception as e:
        if isinstance(e, DecryptionError):
            raise
        raise DecryptionError(str(e)) from e
