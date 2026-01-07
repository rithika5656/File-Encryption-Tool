"""
File Encryption Tool - Unit tests
"""

import unittest
import os
import tempfile
from encryption import encrypt_file, decrypt_file, generate_key_from_password


class TestEncryption(unittest.TestCase):
    
    def setUp(self):
        """Create temporary test files"""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, 'test.txt')
        self.test_content = b'This is a test file for encryption!'
        
        with open(self.test_file, 'wb') as f:
            f.write(self.test_content)
    
    def tearDown(self):
        """Clean up temporary files"""
        for root, dirs, files in os.walk(self.test_dir, topdown=False):
            for file in files:
                os.remove(os.path.join(root, file))
            for dir in dirs:
                os.rmdir(os.path.join(root, dir))
        os.rmdir(self.test_dir)
    
    def test_key_generation(self):
        """Test key generation from password"""
        password = "test_password"
        key1, salt = generate_key_from_password(password)
        self.assertIsNotNone(key1)
        self.assertEqual(len(salt), 16)
        
        # Same password with same salt should produce same key
        key2, _ = generate_key_from_password(password, salt)
        self.assertEqual(key1, key2)
    
    def test_encrypt_file(self):
        """Test file encryption"""
        password = "secure_password"
        encrypted_path = encrypt_file(self.test_file, password)
        
        self.assertTrue(os.path.exists(encrypted_path))
        self.assertTrue(encrypted_path.endswith('.encrypted'))
        
        # Encrypted file should be larger (due to salt and encryption overhead)
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        self.assertGreater(len(encrypted_data), len(self.test_content))
    
    def test_decrypt_file(self):
        """Test file decryption"""
        password = "secure_password"
        encrypted_path = encrypt_file(self.test_file, password)
        decrypted_path = decrypt_file(encrypted_path, password)
        
        self.assertTrue(os.path.exists(decrypted_path))
        
        # Verify decrypted content matches original
        with open(decrypted_path, 'rb') as f:
            decrypted_content = f.read()
        self.assertEqual(decrypted_content, self.test_content)
    
    def test_wrong_password(self):
        """Test decryption with wrong password"""
        password = "correct_password"
        wrong_password = "wrong_password"
        
        encrypted_path = encrypt_file(self.test_file, password)
        
        with self.assertRaises(ValueError):
            decrypt_file(encrypted_path, wrong_password)
    
    def test_custom_output_path(self):
        """Test decryption with custom output path"""
        password = "secure_password"
        custom_output = os.path.join(self.test_dir, 'custom_decrypted.txt')
        
        encrypted_path = encrypt_file(self.test_file, password)
        decrypted_path = decrypt_file(encrypted_path, password, custom_output)
        
        self.assertEqual(decrypted_path, custom_output)
        self.assertTrue(os.path.exists(custom_output))


if __name__ == '__main__':
    unittest.main()
