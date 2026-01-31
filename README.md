# File Encryption Tool

![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

A secure, command-line file encryption utility built with Python. Protect your sensitive documents using industry-standard AES-128 encryption (via Fernet).

## Features

- **Robust Encryption**: Uses Fernet (AES-128 CBC) with PBKDF2HMAC-SHA256 for key derivation.
- **Secure Handling**: Generates unique salts per file and uses `secrets` for cryptographic randomness.
- **CLI Power**: 
    - ✨ **Colored Output**: Visual feedback for success/error states.
    - 🧪 **Dry Run**: Simulate operations without modifying files (`--dry-run`).
    - 🛡️ **Safe Mode**: Create backups (`--backup`) and securely delete originals (`--delete-original`).
- **Developer Friendly**: Type-hinted codebase with comprehensive logging.

## Project Structure

```
File-Encryption-Tool/
├── cli.py              # Main entry point and CLI logic
├── encryption.py       # Core cryptographic implementation
├── requirements.txt    # Project dependencies
└── README.md           # Documentation
```

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

### Encrypt a File
```bash
python cli.py encrypt secret.txt
```
*Prompts for password securely.*

**Options:**
- `--backup`: Create `secret.txt.bak` before encrypting.
- `--delete-original`: Securely overwrite and delete the original file after success.
- `--dry-run`: See what would happen without doing it.

### Decrypt a File
```bash
python cli.py decrypt secret.txt.encrypted
```

### Get Help
```bash
python cli.py --help
python cli.py encrypt --help
```

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `EncryptionError` | General failure | Check file permissions and disk space. |
| `DecryptionError` | Wrong password | Ensure you are using the correct password. Key derivation is case-sensitive. |
| `File too short` | Corrupted file | The file is smaller than the required salt size (16 bytes). |

## Security Notes
- **Memory Usage**: This tool reads files into memory. Avoid processing files larger than your available RAM (warning trigger at 500MB).
- **Passwords**: Use strong passwords. Weak passwords are susceptible to brute-force attacks despite PBKDF2 stretching.

## License
MIT License - Copyright (c) 2024 Rithika
