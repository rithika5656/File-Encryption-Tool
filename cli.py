"""
Command-line interface for File Encryption Tool
"""

import argparse
import sys
import time
import getpass
import contextlib
import os
import shutil
import platform
import logging
from pathlib import Path
from typing import Optional, List, NoReturn, TextIO

# Try to import colorama
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLORS = True
except ImportError:
    HAS_COLORS = False
    
from encryption import encrypt_file, decrypt_file, EncryptionError, DecryptionError

# Constants
APP_NAME = "File Encryption Tool"
VERSION = "1.1.0"

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("CLI")

class Colors:
    """Helper class for terminal colors."""
    @staticmethod
    def red(text: str) -> str:
        return f"{Fore.RED}{text}{Style.RESET_ALL}" if HAS_COLORS else text
    
    @staticmethod
    def green(text: str) -> str:
        return f"{Fore.GREEN}{text}{Style.RESET_ALL}" if HAS_COLORS else text
        
    @staticmethod
    def yellow(text: str) -> str:
        return f"{Fore.YELLOW}{text}{Style.RESET_ALL}" if HAS_COLORS else text
        
    @staticmethod
    def cyan(text: str) -> str:
        return f"{Fore.CYAN}{text}{Style.RESET_ALL}" if HAS_COLORS else text

def print_banner() -> None:
    """Prints the application banner."""
    banner = f"""
    {Colors.cyan('╔══════════════════════════════════════╗')}
    {Colors.cyan('║      File Encryption Tool v' + VERSION + '     ║')}
    {Colors.cyan('╚══════════════════════════════════════╝')}
    """
    print(banner)

def get_parser() -> argparse.ArgumentParser:
    """Create and return the argument parser with all flags."""
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} - Encrypt and decrypt files securely",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Global flags
    parser.add_argument('-v', '--version', action='store_true', help='Show detailed version info')
    parser.add_argument('-q', '--quiet', action='store_true', help="Suppress non-error output")
    parser.add_argument('--verbose', action='store_true', help="Show debug information")
    parser.add_argument('--no-color', action='store_true', help="Disable colored output")
    parser.add_argument('--dry-run', action='store_true', help="Simulate actions without modifying files")
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('file', help='Path to file to encrypt')
    encrypt_parser.add_argument('-p', '--password', help='Encryption password')
    encrypt_parser.add_argument('--delete-original', action='store_true', help="Securely delete original file after encryption")
    encrypt_parser.add_argument('--backup', action='store_true', help="Create a backup before encrypting")
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('file', help='Path to encrypted file')
    decrypt_parser.add_argument('-p', '--password', help='Decryption password')
    decrypt_parser.add_argument('-o', '--output', help='Output path for decrypted file')
    decrypt_parser.add_argument('-f', '--force', action='store_true', help="Overwrite existing output files")
    decrypt_parser.add_argument('--dry-run', action='store_true', help="Simulate decryption")
    
    return parser

def print_error(msg: str) -> None:
    """Print error message to stderr."""
    print(f"{Colors.red('✗ Error:')} {msg}", file=sys.stderr)

def print_success(msg: str, quiet: bool = False) -> None:
    """Print success message."""
    if not quiet:
        print(f"{Colors.green('✓')} {msg}")

def print_info(msg: str, quiet: bool = False) -> None:
    """Print info message."""
    if not quiet:
        print(msg)

def secure_delete(path: Path) -> None:
    """Overwrite a file with random data before deleting it (basic secure delete)."""
    if not path.exists():
        return
    try:
        length = path.stat().st_size
        with open(path, "wb") as f:
            f.write(os.urandom(length))
        path.unlink()
    except OSError as e:
        print_error(f"Secure delete failed: {e}")

def create_backup(path: Path) -> Optional[Path]:
    """Create a .bak copy of the file."""
    backup_path = path.with_suffix(path.suffix + '.bak')
    try:
        shutil.copy2(path, backup_path)
        return backup_path
    except OSError as e:
        print_error(f"Backup failed: {e}")
        return None

def handle_encrypt(args: argparse.Namespace) -> None:
    """Handle the encrypt command logic."""
    file_path = Path(args.file)
    
    if not file_path.exists():
        print_error(f"File not found: {file_path}")
        sys.exit(1)
        
    if args.dry_run:
        print_info(f"{Colors.yellow('[DRY RUN]')} Would encrypt: {file_path}")
        if args.backup:
            print_info(f"{Colors.yellow('[DRY RUN]')} Would invoke backup")
        if args.delete_original:
            print_info(f"{Colors.yellow('[DRY RUN]')} Would securely delete original")
        return

    # Password handling
    password = args.password
    if not password:
        password = getpass.getpass("Enter encryption password: ")
        confirm = getpass.getpass("Confirm encryption password: ")
        if password != confirm:
            print_error("Passwords do not match")
            sys.exit(1)
            
    if len(password) < 4:
         print_info(Colors.yellow("Warning: Password is very short!"))

    start_time = time.perf_counter()
    
    try:
        if args.backup:
            bak = create_backup(file_path)
            if bak:
                print_info(f"Backup created: {bak}")

        # Perform encryption
        if args.quiet:
            with contextlib.redirect_stdout(None):
                output_path = encrypt_file(str(file_path), password)
        else:
            output_path = encrypt_file(str(file_path), password)
            
        elapsed = time.perf_counter() - start_time
        print_success(f"File encrypted successfully: {output_path}", args.quiet)
        
        if args.verbose:
            print_info(f"Operation completed in {elapsed:.4f} seconds")
            
        if args.delete_original:
            secure_delete(file_path)
            print_info(f"Original file securely deleted.", args.quiet)
                
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

def handle_decrypt(args: argparse.Namespace) -> None:
    """Handle the decrypt command logic."""
    file_path = Path(args.file)
    
    if not file_path.exists():
        print_error(f"File not found: {file_path}")
        sys.exit(1)
        
    if args.dry_run or (hasattr(args, 'dry_run') and args.dry_run): # Check attr existence for safety
        print_info(f"{Colors.yellow('[DRY RUN]')} Would decrypt: {file_path}")
        return

    password = args.password
    if not password:
        password = getpass.getpass("Enter decryption password: ")

    start_time = time.perf_counter()
    target_path_str = args.output
    
    try:
        # We pass output path to lib which handles collision logic now? 
        # No, lib overwrites. We should check if not force.
        # But we don't know output path easily without logic duplic. 
        # Let's trust library or do a check.
        # If output path NOT specified, we derive it to check 'exists'
        if not target_path_str:
             if str(file_path).endswith('.encrypted'):
                derived = str(file_path)[:-10]
             else:
                derived = str(file_path) + '.decrypted'
        else:
             derived = target_path_str
             
        if os.path.exists(derived) and not args.force:
            if not args.quiet:
                response = input(f"Output file {derived} exists. Overwrite? [y/N]: ")
                if response.lower() != 'y':
                    print_info("Cancelled.")
                    sys.exit(0)

        if args.quiet:
            with contextlib.redirect_stdout(None):
                out = decrypt_file(str(file_path), password, target_path_str)
        else:
            out = decrypt_file(str(file_path), password, target_path_str)
            
        elapsed = time.perf_counter() - start_time
        print_success(f"File decrypted successfully: {out}", args.quiet)
        
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

def print_version_info():
    print(f"{APP_NAME} v{VERSION}")
    print(f"Python: {sys.version}")
    print(f"Platform: {platform.platform()}")
    print(f"System: {platform.system()} {platform.release()}")

def main():
    parser = get_parser()
    args = parser.parse_args()
    
    # Handle Global flag: no-color
    global HAS_COLORS
    if args.no_color:
        HAS_COLORS = False

    # Handle Global flag: version
    if args.version:
        print_version_info()
        sys.exit(0)
        
    if not args.quiet:
        print_banner()

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
        print(f"\n{Colors.yellow('Operation cancelled by user.')}")
        sys.exit(130)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        logger.exception("Unexpected error")
        sys.exit(1)

if __name__ == '__main__':
    main()
