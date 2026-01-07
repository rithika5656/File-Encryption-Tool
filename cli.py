"""
Command-line interface for File Encryption Tool
"""

import argparse
import sys
from encryption import encrypt_file, decrypt_file


def main():
    parser = argparse.ArgumentParser(
        description="File Encryption Tool - Encrypt and decrypt files using password-based encryption"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('file', help='Path to file to encrypt')
    encrypt_parser.add_argument('-p', '--password', help='Encryption password')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('file', help='Path to encrypted file')
    decrypt_parser.add_argument('-p', '--password', help='Decryption password')
    decrypt_parser.add_argument('-o', '--output', help='Output path for decrypted file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'encrypt':
            password = args.password
            if not password:
                password = input("Enter encryption password: ")
            encrypt_file(args.file, password)
        
        elif args.command == 'decrypt':
            password = args.password
            if not password:
                password = input("Enter decryption password: ")
            decrypt_file(args.file, password, args.output)
    
    except FileNotFoundError as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"✗ Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
