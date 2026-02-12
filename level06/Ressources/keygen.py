#!/usr/bin/env python
"""
OverRide Level06 - Serial Keygen

This script generates valid serial numbers for the level06 authentication system.
The serial is computed using a deterministic algorithm based on the login string.

Usage:
    python keygen.py <login>
    python keygen.py              (interactive mode)

Examples:
    python keygen.py "helloo"
    Output: Login: helloo, Serial: 6232827
    
    python keygen.py "aaaaaa"
    Output: Login: aaaaaa, Serial: 6234456
"""

def generate_serial(login):
    """
    Generate a valid serial number for the given login.
    
    Algorithm (reverse-engineered from the binary):
    1. Initial seed: (login[3] XOR 0x1337) + 0x5eeded
    2. For each character: serial += (char XOR serial) % 0x539
    
    Args:
        login (str): Login string (must be >= 6 characters, all printable)
    
    Returns:
        int: Valid serial number, or None if validation fails
    """
    # Remove trailing newline if present
    login = login.rstrip('\n')
    
    # Validation: Login must be at least 6 characters
    if len(login) < 6:
        print("Error: Login must be at least 6 characters")
        return None
    
    # Validation: All characters must be printable (ASCII >= 0x20)
    for c in login:
        if ord(c) < 0x20:
            print("Error: All characters must be printable (ASCII >= 0x20)")
            return None
    
    # Serial generation algorithm
    # Step 1: Initialize with 4th character XORed with magic value
    serial = (ord(login[3]) ^ 0x1337) + 0x5eeded
    
    # Step 2: Process each character in the login
    for char in login:
        serial += (ord(char) ^ serial) % 0x539
    
    # Keep as 32-bit unsigned integer
    return serial & 0xFFFFFFFF


def main():
    """Main function for interactive or command-line usage."""
    import sys
    
    if len(sys.argv) > 1:
        # Command-line mode: use argument as login
        login = sys.argv[1]
    else:
        # Interactive mode: prompt for login
        try:
            login = raw_input("Enter login: ").strip()
        except NameError:
            # Python 3 compatibility
            login = input("Enter login: ").strip()
    
    # Generate serial
    serial = generate_serial(login)
    
    if serial is not None:
        print("Login: %s" % login)
        print("Serial: %d" % serial)
        return 0
    else:
        return 1


if __name__ == "__main__":
    exit(main())
