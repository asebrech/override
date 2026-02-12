# Walkthrough

## 1. Download the binary

```bash
scp -P 2222 level06@localhost:~/level06 .
# Password: h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
```

## 2. Analyze with Ghidra

Open the binary in Ghidra and examine the `main` and `auth` functions.

## 3. Understand the program flow

**main():**
1. Prompts for login (32 bytes max via `fgets`)
2. Prompts for serial (unsigned int via `scanf`)
3. Calls `auth(login, serial)`
4. If `auth()` returns 0 → Authenticated → spawns shell
5. Otherwise, exits with failure

**auth(login, serial):**
1. Removes newline from login
2. Validates login length >= 6 characters
3. Calls `ptrace(PTRACE_TRACEME)` for anti-debugging
4. Validates all characters are printable (ASCII >= 0x20)
5. Computes serial using algorithm
6. Compares computed serial with user-provided serial
7. Returns 0 if match, 1 if no match

## 4. Reverse engineer the serial algorithm

From Ghidra decompilation of `auth()`:

```c
// Initial seed from 4th character
computed_serial = (login[3] ^ 0x1337) + 0x5eeded;

// For each character in login
for (i = 0; i < len; i++) {
    computed_serial += (login[i] ^ computed_serial) % 0x539;
}

// Compare with user input
if (serial == computed_serial) {
    return 0;  // Success!
}
```

**Key components:**
- `0x1337` - XOR magic constant
- `0x5eeded` - Addition constant
- `0x539` (1337 decimal) - Modulo divisor
- Algorithm is deterministic (same input = same output)

## 5. Create keygen script

Create `keygen.py`:

```python
#!/usr/bin/env python

def generate_serial(login):
    # Remove newline
    login = login.rstrip('\n')
    
    # Validate length >= 6
    if len(login) < 6:
        print("Error: Login must be at least 6 characters")
        return None
    
    # Validate printable characters
    for c in login:
        if ord(c) < 0x20:
            print("Error: All characters must be printable")
            return None
    
    # Serial algorithm
    serial = (ord(login[3]) ^ 0x1337) + 0x5eeded
    
    for char in login:
        serial += (ord(char) ^ serial) % 0x539
    
    return serial & 0xFFFFFFFF

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        login = sys.argv[1]
    else:
        login = raw_input("Enter login: ").strip()
    
    serial = generate_serial(login)
    if serial is not None:
        print("Login: %s" % login)
        print("Serial: %d" % serial)
```

## 6. Test the keygen

```bash
python keygen.py "helloo"
```

**Output:**
```
Login: helloo
Serial: 6232827
```

## 7. Additional test cases

```bash
# Test with simple login
python keygen.py "aaaaaa"
# Output: Login: aaaaaa, Serial: 6234456

# Test with another login
python keygen.py "test00"
# Output: Login: test00, Serial: 6232494
```

## 8. Connect to level06

```bash
ssh level06@localhost -p 2222
# Password: h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
```

## 9. Execute the exploit

```bash
./level06
# When prompted:
-> Enter Login: helloo
-> Enter Serial: 6232827
```

**Output:**
```
***********************************
*               level06           *
***********************************
-> Enter Login: helloo
***********************************
***** NEW ACCOUNT DETECTED ********
***********************************
-> Enter Serial: 6232827
Authenticated!
$
```

## 10. Get the flag

```bash
whoami
# level07
cat /home/users/level07/.pass
```

## 11. Flag

```
GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8
```

## Notes

### Anti-Debugging Bypass

The `ptrace(PTRACE_TRACEME)` call prevents debugging:
- Returns `-1` if already being traced (e.g., in GDB)
- Shows "TAMPERING DETECTED" message and fails authentication

**Solution:** Run the program normally (not in GDB). Since we have a keygen, we don't need to debug the binary.

### Algorithm Properties

The serial generation is:
- **Deterministic**: Same login always produces same serial
- **Irreversible**: Given a serial, can't easily derive the login
- **Character-dependent**: Each character affects the final serial
- **Position-sensitive**: Character order matters (4th char is seed)
