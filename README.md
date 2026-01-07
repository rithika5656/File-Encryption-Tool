# File Encryption Tool

A simple and secure Python application to encrypt and decrypt files using password-based encryption.

## Features

- **Password-based encryption** using Fernet (symmetric encryption)
- **PBKDF2 key derivation** for secure password handling
- **Salt-based security** to prevent rainbow table attacks
- **Command-line interface** for easy usage
- **Comprehensive error handling**
- **Unit tests** for reliability

## Requirements

- Python 3.7+
- cryptography library

## Installation

1. Clone the repository:
```bash
git clone https://github.com/rithika5656/File-Encryption-Tool.git
cd File-Encryption-Tool
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Command Line Interface

**Encrypt a file:**
```bash
python cli.py encrypt path/to/file.txt -p mypassword
```

**Decrypt a file:**
```bash
python cli.py decrypt path/to/file.txt.encrypted -p mypassword
```

**Decrypt with custom output path:**
```bash
python cli.py decrypt path/to/file.encrypted -p mypassword -o output.txt
```

### Python API

```python
from encryption import encrypt_file, decrypt_file

# Encrypt a file
encrypt_file('document.pdf', 'secure_password')

# Decrypt a file
decrypt_file('document.pdf.encrypted', 'secure_password')
```

## How It Works

1. **Key Derivation**: Passwords are converted to encryption keys using PBKDF2 with SHA-256
2. **Salt**: A random 16-byte salt is generated for each encryption
3. **Encryption**: Files are encrypted using Fernet (AES-128 in CBC mode)
4. **Storage**: The salt is prepended to the encrypted data and stored together

## Running Tests

```bash
python -m unittest test_encryption.py
```

## Security Notes

- Passwords should be strong and kept confidential
- Each file gets a unique salt, even with the same password
- Encrypted files have the `.encrypted` extension by default
- The tool uses industry-standard cryptographic libraries

## License

MIT License

## Author

Rithika
