#!/usr/bin/env python3
"""
Password Cracker - Ethical Hacking Tools Suite
Educational and Testing Purposes Only

Supports multiple hash algorithms and attack methods:
- Dictionary attacks
- Brute force attacks
- Rainbow table attacks (basic)
- Hash algorithms: MD5, SHA1, SHA256, SHA512, bcrypt, etc.
"""

import hashlib
import itertools
import string
import threading
import time
from datetime import datetime
import argparse
import os
import sys

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    print("[!] Warning: bcrypt not available. bcrypt cracking disabled.")

try:
    from passlib.hash import *
    PASSLIB_AVAILABLE = True
except ImportError:
    PASSLIB_AVAILABLE = False
    print("[!] Warning: passlib not available. Some hash types disabled.")

from ethical_hacking_tools.utils.logger import setup_logger, log_security_event

class PasswordCracker:
    """
    Advanced password cracking tool with multiple attack methods
    """
    
    def __init__(self):
        self.logger = setup_logger('password_cracker')
        self.found_passwords = {}
        self.attempts = 0
        self.start_time = None
        self.stop_flag = False
        
        # Common password patterns
        self.common_passwords = [
            'password', '123456', 'password123', 'admin', 'root',
            'qwerty', 'abc123', 'letmein', 'welcome', 'monkey',
            '1234567890', 'password1', '123123', 'dragon', 'master',
            'hello', 'freedom', 'whatever', 'qazwsx', 'trustno1',
            '654321', 'jordan23', 'harley', 'password12', 'fuckyou',
            '123', '1234', '12345', '123456', '1234567', '12345678',
            '123456789', '1234567890', 'qwerty', 'abc', 'abcd',
            'abc123', '111111', '000000', 'iloveyou', 'dragon',
            'sunshine', 'princess', 'football', 'charlie', 'aa123456'
        ]
        
        # Character sets for brute force
        self.char_sets = {
            'lower': string.ascii_lowercase,
            'upper': string.ascii_uppercase,
            'digits': string.digits,
            'special': '!@#$%^&*()_+-=[]{}|;:,.<>?',
            'alphanum': string.ascii_letters + string.digits,
            'all': string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }
    
    def hash_password(self, password, algorithm='md5'):
        """
        Hash a password using specified algorithm
        """
        password = password.encode('utf-8')
        
        if algorithm.lower() == 'md5':
            return hashlib.md5(password).hexdigest()
        elif algorithm.lower() == 'sha1':
            return hashlib.sha1(password).hexdigest()
        elif algorithm.lower() == 'sha256':
            return hashlib.sha256(password).hexdigest()
        elif algorithm.lower() == 'sha512':
            return hashlib.sha512(password).hexdigest()
        elif algorithm.lower() == 'sha224':
            return hashlib.sha224(password).hexdigest()
        elif algorithm.lower() == 'sha384':
            return hashlib.sha384(password).hexdigest()
        elif algorithm.lower() == 'blake2b':
            return hashlib.blake2b(password).hexdigest()
        elif algorithm.lower() == 'blake2s':
            return hashlib.blake2s(password).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def verify_password(self, password, target_hash, algorithm='md5', salt=None):
        """
        Verify if password matches target hash
        """
        try:
            if algorithm.lower() == 'bcrypt':
                if not BCRYPT_AVAILABLE:
                    return False
                return bcrypt.checkpw(password.encode('utf-8'), target_hash.encode('utf-8'))
            
            elif algorithm.lower() in ['md5', 'sha1', 'sha256', 'sha512', 'sha224', 'sha384']:
                if salt:
                    password_with_salt = password + salt
                else:
                    password_with_salt = password
                
                computed_hash = self.hash_password(password_with_salt, algorithm)
                return computed_hash.lower() == target_hash.lower()
            
            elif PASSLIB_AVAILABLE:
                # Use passlib for more complex hash types
                if algorithm.lower() == 'pbkdf2_sha256':
                    return pbkdf2_sha256.verify(password, target_hash)
                elif algorithm.lower() == 'pbkdf2_sha512':
                    return pbkdf2_sha512.verify(password, target_hash)
                elif algorithm.lower() == 'argon2':
                    return argon2.verify(password, target_hash)
                elif algorithm.lower() == 'scrypt':
                    return scrypt.verify(password, target_hash)
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error verifying password: {e}")
            return False
    
    def dictionary_attack(self, wordlist_file, target_hash, algorithm='md5', salt=None):
        """
        Perform dictionary attack using wordlist
        """
        self.logger.info(f"Starting dictionary attack on hash: {target_hash[:16]}...")
        print(f"\n[+] Starting dictionary attack...")
        print(f"[+] Target hash: {target_hash[:16]}...")
        print(f"[+] Algorithm: {algorithm}")
        print(f"[+] Wordlist: {wordlist_file}")
        
        if not os.path.exists(wordlist_file):
            print(f"[!] Error: Wordlist file '{wordlist_file}' not found")
            return None
        
        self.start_time = time.time()
        self.attempts = 0
        
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if self.stop_flag:
                        break
                    
                    password = line.strip()
                    if not password:
                        continue
                    
                    self.attempts += 1
                    
                    # Try password as-is
                    if self.verify_password(password, target_hash, algorithm, salt):
                        self.found_passwords[target_hash] = password
                        elapsed_time = time.time() - self.start_time
                        print(f"\n[+] PASSWORD FOUND!")
                        print(f"[+] Password: {password}")
                        print(f"[+] Attempts: {self.attempts}")
                        print(f"[+] Time: {elapsed_time:.2f} seconds")
                        
                        log_security_event(
                            self.logger,
                            'password_cracked',
                            target_hash[:16],
                            f"Password: {password}"
                        )
                        return password
                    
                    # Try common variations
                    variations = self.generate_variations(password)
                    for variation in variations:
                        if self.stop_flag:
                            break
                        
                        self.attempts += 1
                        if self.verify_password(variation, target_hash, algorithm, salt):
                            self.found_passwords[target_hash] = variation
                            elapsed_time = time.time() - self.start_time
                            print(f"\n[+] PASSWORD FOUND!")
                            print(f"[+] Password: {variation}")
                            print(f"[+] Attempts: {self.attempts}")
                            print(f"[+] Time: {elapsed_time:.2f} seconds")
                            
                            log_security_event(
                                self.logger,
                                'password_cracked',
                                target_hash[:16],
                                f"Password: {variation}"
                            )
                            return variation
                    
                    # Progress indicator
                    if self.attempts % 1000 == 0:
                        elapsed_time = time.time() - self.start_time
                        rate = self.attempts / elapsed_time if elapsed_time > 0 else 0
                        print(f"[+] Attempts: {self.attempts}, Rate: {rate:.0f} p/s", end='\r')
        
        except KeyboardInterrupt:
            print(f"\n[!] Dictionary attack interrupted by user")
            self.stop_flag = True
        except Exception as e:
            self.logger.error(f"Error in dictionary attack: {e}")
            print(f"[!] Error: {e}")
        
        elapsed_time = time.time() - self.start_time
        print(f"\n[!] Dictionary attack completed")
        print(f"[!] Total attempts: {self.attempts}")
        print(f"[!] Time elapsed: {elapsed_time:.2f} seconds")
        print(f"[!] Password not found in wordlist")
        
        return None
    
    def generate_variations(self, password):
        """
        Generate common password variations
        """
        variations = []
        
        # Add numbers
        for i in range(10):
            variations.append(password + str(i))
            variations.append(str(i) + password)
        
        # Add common suffixes
        suffixes = ['123', '1234', '12345', '!', '@', '#', '$', '%']
        for suffix in suffixes:
            variations.append(password + suffix)
        
        # Case variations
        variations.append(password.upper())
        variations.append(password.lower())
        variations.append(password.capitalize())
        
        # Leet speak variations
        leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
        leet_password = password.lower()
        for char, replacement in leet_map.items():
            leet_password = leet_password.replace(char, replacement)
        variations.append(leet_password)
        
        return variations
    
    def brute_force_attack(self, target_hash, algorithm='md5', max_length=6, char_set='alphanum'):
        """
        Perform brute force attack
        """
        self.logger.info(f"Starting brute force attack on hash: {target_hash[:16]}...")
        print(f"\n[+] Starting brute force attack...")
        print(f"[+] Target hash: {target_hash[:16]}...")
        print(f"[+] Algorithm: {algorithm}")
        print(f"[+] Max length: {max_length}")
        print(f"[+] Character set: {char_set}")
        
        if char_set not in self.char_sets:
            print(f"[!] Error: Unknown character set '{char_set}'")
            return None
        
        characters = self.char_sets[char_set]
        self.start_time = time.time()
        self.attempts = 0
        
        try:
            for length in range(1, max_length + 1):
                if self.stop_flag:
                    break
                
                print(f"[+] Trying length {length}...")
                
                for password_tuple in itertools.product(characters, repeat=length):
                    if self.stop_flag:
                        break
                    
                    password = ''.join(password_tuple)
                    self.attempts += 1
                    
                    if self.verify_password(password, target_hash, algorithm):
                        self.found_passwords[target_hash] = password
                        elapsed_time = time.time() - self.start_time
                        print(f"\n[+] PASSWORD FOUND!")
                        print(f"[+] Password: {password}")
                        print(f"[+] Attempts: {self.attempts}")
                        print(f"[+] Time: {elapsed_time:.2f} seconds")
                        
                        log_security_event(
                            self.logger,
                            'password_cracked',
                            target_hash[:16],
                            f"Password: {password}"
                        )
                        return password
                    
                    # Progress indicator
                    if self.attempts % 10000 == 0:
                        elapsed_time = time.time() - self.start_time
                        rate = self.attempts / elapsed_time if elapsed_time > 0 else 0
                        print(f"[+] Attempts: {self.attempts}, Rate: {rate:.0f} p/s", end='\r')
        
        except KeyboardInterrupt:
            print(f"\n[!] Brute force attack interrupted by user")
            self.stop_flag = True
        except Exception as e:
            self.logger.error(f"Error in brute force attack: {e}")
            print(f"[!] Error: {e}")
        
        elapsed_time = time.time() - self.start_time
        print(f"\n[!] Brute force attack completed")
        print(f"[!] Total attempts: {self.attempts}")
        print(f"[!] Time elapsed: {elapsed_time:.2f} seconds")
        print(f"[!] Password not found")
        
        return None
    
    def hybrid_attack(self, wordlist_file, target_hash, algorithm='md5', max_length=4):
        """
        Hybrid attack: dictionary + brute force
        """
        self.logger.info(f"Starting hybrid attack on hash: {target_hash[:16]}...")
        print(f"\n[+] Starting hybrid attack...")
        print(f"[+] Target hash: {target_hash[:16]}...")
        print(f"[+] Algorithm: {algorithm}")
        print(f"[+] Wordlist: {wordlist_file}")
        print(f"[+] Max brute force length: {max_length}")
        
        # First try dictionary attack
        result = self.dictionary_attack(wordlist_file, target_hash, algorithm)
        if result:
            return result
        
        # If dictionary fails, try brute force on common patterns
        print(f"\n[+] Dictionary attack failed, trying brute force...")
        
        # Try common patterns first
        common_patterns = [
            ('digits', 4),  # 4-digit numbers
            ('lower', 4),   # 4 lowercase letters
            ('alphanum', 3) # 3 alphanumeric characters
        ]
        
        for char_set, length in common_patterns:
            if self.stop_flag:
                break
            
            print(f"[+] Trying {char_set} pattern (length {length})...")
            result = self.brute_force_attack(target_hash, algorithm, length, char_set)
            if result:
                return result
        
        return None
    
    def create_wordlist(self, filename, include_common=True, include_variations=True):
        """
        Create a custom wordlist
        """
        print(f"[+] Creating wordlist: {filename}")
        
        with open(filename, 'w', encoding='utf-8') as f:
            if include_common:
                for password in self.common_passwords:
                    f.write(password + '\n')
            
            if include_variations:
                for password in self.common_passwords:
                    variations = self.generate_variations(password)
                    for variation in variations:
                        f.write(variation + '\n')
        
        print(f"[+] Wordlist created: {filename}")
        return filename
    
    def crack(self, wordlist_file, target_hash, algorithm='md5', attack_type='dictionary', **kwargs):
        """
        Main cracking function
        """
        print(f"\n{'='*60}")
        print("PASSWORD CRACKER - ETHICAL HACKING TOOLS")
        print(f"{'='*60}")
        print(f"[!] WARNING: Use only on systems you own or have permission to test!")
        print(f"[!] Educational and testing purposes only!")
        
        # Reset state
        self.stop_flag = False
        self.found_passwords = {}
        
        start_time = time.time()
        
        try:
            if attack_type == 'dictionary':
                result = self.dictionary_attack(wordlist_file, target_hash, algorithm)
            elif attack_type == 'brute_force':
                max_length = kwargs.get('max_length', 6)
                char_set = kwargs.get('char_set', 'alphanum')
                result = self.brute_force_attack(target_hash, algorithm, max_length, char_set)
            elif attack_type == 'hybrid':
                max_length = kwargs.get('max_length', 4)
                result = self.hybrid_attack(wordlist_file, target_hash, algorithm, max_length)
            else:
                print(f"[!] Unknown attack type: {attack_type}")
                return None
            
            total_time = time.time() - start_time
            
            print(f"\n{'='*60}")
            print("CRACKING SUMMARY")
            print(f"{'='*60}")
            print(f"Target hash: {target_hash[:16]}...")
            print(f"Algorithm: {algorithm}")
            print(f"Attack type: {attack_type}")
            print(f"Total time: {total_time:.2f} seconds")
            print(f"Total attempts: {self.attempts}")
            
            if result:
                print(f"Result: SUCCESS - Password found: {result}")
            else:
                print(f"Result: FAILED - Password not found")
            
            return result
            
        except KeyboardInterrupt:
            print(f"\n[!] Cracking interrupted by user")
            self.stop_flag = True
            return None
        except Exception as e:
            self.logger.error(f"Error in cracking process: {e}")
            print(f"[!] Error: {e}")
            return None

def main():
    """
    Command line interface for Password Cracker
    """
    parser = argparse.ArgumentParser(description='Password Cracker - Ethical Hacking Tools')
    parser.add_argument('-f', '--wordlist', required=True, help='Wordlist file')
    parser.add_argument('-h', '--hash', required=True, help='Hash to crack')
    parser.add_argument('-a', '--algorithm', default='md5', 
                       choices=['md5', 'sha1', 'sha256', 'sha512', 'sha224', 'sha384', 'bcrypt'],
                       help='Hash algorithm')
    parser.add_argument('-t', '--attack-type', default='dictionary',
                       choices=['dictionary', 'brute_force', 'hybrid'],
                       help='Attack type')
    parser.add_argument('-l', '--max-length', type=int, default=6,
                       help='Maximum length for brute force attack')
    parser.add_argument('-c', '--char-set', default='alphanum',
                       choices=['lower', 'upper', 'digits', 'special', 'alphanum', 'all'],
                       help='Character set for brute force attack')
    parser.add_argument('--create-wordlist', help='Create a wordlist file')
    
    args = parser.parse_args()
    
    cracker = PasswordCracker()
    
    if args.create_wordlist:
        cracker.create_wordlist(args.create_wordlist)
        return
    
    cracker.crack(
        args.wordlist,
        args.hash,
        args.algorithm,
        args.attack_type,
        max_length=args.max_length,
        char_set=args.char_set
    )

if __name__ == "__main__":
    main()
