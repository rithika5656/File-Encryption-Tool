"""
Command-line interface for File Encryption Tool
"""

import argparse
import sys
import time
import getpass
import contextlib
import os
from pathlib import Path
from typing import Optional, List
from encryption import encrypt_file, decrypt_file

# Constants
APP_NAME = "File Encryption Tool"
VERSION = "1.0.0"

def get_parser() -> argparse.ArgumentParser:
    """
    Create and return the argument parser with all flags
    """
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} - Encrypt and decrypt files securely",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Global flags
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {VERSION}')
    parser.add_argument('-q', '--quiet', action='store_true', help="Suppress non-error output")
    parser.add_argument('--verbose', action='store_true', help="Show debug information")
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('file', help='Path to file to encrypt')
    encrypt_parser.add_argument('-p', '--password', help='Encryption password (warning: visible in history)')
    encrypt_parser.add_argument('--delete-original', action='store_true', help="Delete original file after successful encryption")
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('file', help='Path to encrypted file')
    decrypt_parser.add_argument('-p', '--password', help='Decryption password (warning: visible in history)')
    decrypt_parser.add_argument('-o', '--output', help='Output path for decrypted file')
    decrypt_parser.add_argument('-f', '--force', action='store_true', help="Overwrite existing output files without prompting")
    
    return parser

def print_error(msg: str) -> None:
    """Print error message to stderr"""
    print(f"✗ Error: {msg}", file=sys.stderr)

def print_success(msg: str, quiet: bool = False) -> None:
    """Print success message if not quiet"""
    if not quiet:
        print(f"✓ {msg}")

def print_info(msg: str, quiet: bool = False) -> None:
    """Print info message if not quiet"""
    if not quiet:
        print(msg)

def handle_encrypt(args: argparse.Namespace) -> None:
    """
    Handle the encrypt command logic
    """
    file_path = Path(args.file)
    
    # validation
    if not file_path.exists():
        print_error(f"File not found: {file_path}")
        sys.exit(1)
    if not file_path.is_file():
        print_error(f"Not a file: {file_path}")
        sys.exit(1)
        
    # password handling
    password = args.password
    if not password:
        try:
            p1 = getpass.getpass("Enter encryption password: ")
            p2 = getpass.getpass("Confirm encryption password: ")
            if p1 != p2:
                print_error("Passwords do not match")
                sys.exit(1)
            password = p1
        except getpass.GetPassWarning:
            print_error("Warning: input echoed (terminal issue)")
            
    start_time = time.perf_counter()
    
    try:
        # We assume library prints, suppress if quiet using context redirect check?
        # The library prints to stdout. We can catch it or let it be.
        # Since we want to control output, let's redirect logic if quiet.
        if args.quiet:
            with contextlib.redirect_stdout(None):
                output_path = encrypt_file(str(file_path), password)
        else:
            output_path = encrypt_file(str(file_path), password)
            
        elapsed = time.perf_counter() - start_time
        
        if args.verbose:
            print_info(f"debug: Operation completed in {elapsed:.2f} seconds")
            
        if args.delete_original:
            try:
                file_path.unlink()
                print_info(f"Original file deleted: {file_path}", args.quiet)
            except OSError as e:
                print_error(f"Failed to delete original file: {e}")
                
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

def handle_decrypt(args: argparse.Namespace) -> None:
    """
    Handle the decrypt command logic
    """
    file_path = Path(args.file)
    
    if not file_path.exists():
        print_error(f"File not found: {file_path}")
        sys.exit(1)
        
    password = args.password
    if not password:
        password = getpass.getpass("Enter decryption password: ")
        
    # Logic to determine output path beforehand for checking overwrite
    # Note: the library does this internally if not provided, but we duplicate logic slightly 
    # to check existence if we want to be safe before passing to library?
    # Actually, let's trust the library to handle output creation, but checking overwrite needs path.
    # The library `decrypt_file` calculates output path if None.
    # Let's simple pass to library, but if library doesn't support 'force', we might failing on overwrite?
    # Viewing encryption.py: It simply opens for 'wb' (Line 109), effectively overwriting.
    # So 'force' is actually about PROMPTING before overwriting.
    # To implement this safely, we need to know the target path.
    
    target_path_str = args.output
    if target_path_str is None:
        if str(file_path).endswith('.encrypted'):
            target_path_str = str(file_path)[:-10]
        else:
            target_path_str = str(file_path) + '.decrypted'
            
    target_path = Path(target_path_str)
    
    if target_path.exists() and not args.force:
        # Prompt user
        if not args.quiet:
            confirm = input(f"Output file '{target_path}' exists. Overwrite? [y/N]: ").lower()
            if confirm != 'y':
                print_info("Operation cancelled.", args.quiet)
                sys.exit(0)
    
    start_time = time.perf_counter()
    
    try:
        if args.quiet:
            with contextlib.redirect_stdout(None):
                decrypt_file(str(file_path), password, str(target_path))
        else:
            decrypt_file(str(file_path), password, str(target_path))
            
        elapsed = time.perf_counter() - start_time
        if args.verbose:
            print_info(f"debug: Operation completed in {elapsed:.2f} seconds")
            
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

def main():
    parser = get_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.command == 'encrypt':
            handle_encrypt(args)
        elif args.command == 'decrypt':
            handle_decrypt(args)
        
        sys.exit(0)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(130)
    except PermissionError:
        print_error("Permission denied. Check file permissions.")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
