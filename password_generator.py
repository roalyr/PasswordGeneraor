#  This work is marked with CC0 1.0 Universal 

import hashlib
import base64
import getpass
import os
import subprocess
from hashlib import pbkdf2_hmac
import time
import gc

def clear_screen():
    """Clear the terminal screen in a cross-platform way."""
    if os.name == 'nt':  # For Windows
        os.system('cls')
    else:  # For Unix-like systems
        subprocess.call('clear', shell=True)

def generate_password(master_password, account_name, length=16, special_chars=True, uppercase=True, numbers_only=False):
    """
    Generate a deterministic password based on the master password and account name.

    Args:
        master_password (str): The master password.
        account_name (str): The name of the account.
        length (int): Desired length of the password.
        special_chars (bool): Include special characters in the password.
        uppercase (bool): Include uppercase letters in the password.
        numbers_only (bool): Generate a password using only numbers.

    Returns:
        str: Generated password.
    """
    # Use PBKDF2 for key stretching
    salt = account_name.encode()  # Use account name as the salt
    derived_key = pbkdf2_hmac('sha256', master_password, salt, 100000)

    if numbers_only:
        # Generate numbers-only password
        password = ''.join(str(byte % 10) for byte in derived_key)[:length]
    else:
        # Convert the derived key to a Base64 string
        password = base64.urlsafe_b64encode(derived_key).decode('utf-8')[:length]
        
        # Optionally include special characters
        if special_chars:
            specials = "!@#$%^&*()-_=+"
            for i in range(length // 4):  # Replace some characters with special ones
                idx = i * 3 % len(password)  # Spread changes
                password = password[:idx] + specials[i % len(specials)] + password[idx + 1:]
        
        # Optionally include mixed case
        if uppercase:
            mixed_case_password = ""
            for i, char in enumerate(password):
                if char.isalpha():  # Only apply to alphabetic characters
                    # Use the derived key to determine case
                    if derived_key[i % len(derived_key)] % 2 == 0:
                        mixed_case_password += char.upper()
                    else:
                        mixed_case_password += char.lower()
                else:
                    mixed_case_password += char
            password = mixed_case_password

    return password

if __name__ == "__main__":
    try:
        clear_screen()
        print("Welcome to the Password Generator!")
        account_name = input("Enter the account name: ")
        
        # Securely read the master password as a bytearray
        master_password = bytearray(getpass.getpass("Enter your master password: "), 'utf-8')
        length = int(input("Enter desired password length (default 16): ") or 16)
        numbers_only = input("Numbers-only password? (y/n, default n): ").lower() == 'y'

        # Check for secure length if numbers-only is selected
        if numbers_only and length < 12:
            print("Warning: Numbers-only passwords are less secure. Consider using a length of at least 12.")

        special_chars = not numbers_only and input("Include special characters? (y/n, default y): ").lower() != 'n'
        uppercase = not numbers_only and input("Include uppercase letters? (y/n, default y): ").lower() != 'n'

        # Introduce a small delay to mitigate brute force attempts
        time.sleep(2)

        generated_password = generate_password(
            master_password,
            account_name,
            length=length,
            special_chars=special_chars,
            uppercase=uppercase,
            numbers_only=numbers_only
        )

        print(f"\nGenerated password for '{account_name}':\n")
        print(f"    {generated_password}")
    finally:
        # Securely erase the master password from memory
        if 'master_password' in locals():
            for i in range(len(master_password)):
                master_password[i] = 0  # Overwrite each byte with 0
            del master_password
            gc.collect()  # Force garbage collection

        input('\nPress enter to finish and clear the screen')
        clear_screen()