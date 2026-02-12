# 🔐 Level06 - Serial Keygen Reverse Engineering

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Time to crack a serial number validation system through reverse engineering!

## 📋 Binary Analysis

### 🔍 Architecture & Security

**Platform:** x86 (32-bit ELF)

**Protection Mechanisms:**
- ✅ Stack canary (`__stack_chk_fail`)
- ✅ Anti-debugging (`ptrace`)
- ❌ No ASLR
- ❌ Weak serial validation (deterministic algorithm)

### Decompiled Code

#### Main Function

```c
int main(void)
{
    char login[32];
    unsigned int serial;
    int auth_result;
    
    puts("***********************************");
    puts("*\t\tlevel06\t\t  *");
    puts("***********************************");
    
    // Prompt for login
    printf("-> Enter Login: ");
    fgets(login, 0x20, stdin);
    
    puts("***********************************");
    puts("***** NEW ACCOUNT DETECTED ********");
    puts("***********************************");
    
    // Prompt for serial
    printf("-> Enter Serial: ");
    scanf("%u", &serial);
    
    // Validate credentials
    auth_result = auth(login, serial);
    
    if (auth_result == 0) {
        puts("Authenticated!");
        system("/bin/sh");  // Shell with level07 privileges!
        return 0;
    }
    
    return 1;
}
```

#### Auth Function

```c
int auth(char *login, unsigned int serial)
{
    size_t len;
    unsigned int computed_serial;
    int i;
    
    // Remove trailing newline
    login[strcspn(login, "\n")] = '\0';
    
    // Get login length (max 32)
    len = strnlen(login, 0x20);
    
    // Validation 1: Login must be at least 6 characters
    if (len < 6) {
        return 1;  // FAIL
    }
    
    // Validation 2: Anti-debugging check
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        puts("\x1b[32m.---------------------------.");
        puts("\x1b[31m| !! TAMPERING DETECTED !!  |");
        puts("\x1b[32m\'---------------------------\'");
        return 1;  // FAIL
    }
    
    // Validation 3: All characters must be printable
    for (i = 0; i < len; i++) {
        if (login[i] < ' ') {  // ASCII < 0x20
            return 1;  // FAIL
        }
    }
    
    // SERIAL GENERATION ALGORITHM
    // Step 1: Initial seed from 4th character
    computed_serial = (login[3] ^ 0x1337) + 0x5eeded;
    
    // Step 2: Process each character
    for (i = 0; i < len; i++) {
        computed_serial += (login[i] ^ computed_serial) % 0x539;
    }
    
    // Validation 4: Compare serials
    if (serial == computed_serial) {
        return 0;  // SUCCESS!
    } else {
        return 1;  // FAIL
    }
}
```

### Key Observations

1. **Serial Validation**: Uses a deterministic algorithm to compute expected serial
2. **Magic Constants**:
   - `0x1337` (4919) - XOR constant
   - `0x5eeded` (6221293) - Addition constant
   - `0x539` (1337) - Modulo divisor
3. **Login Requirements**:
   - Length ≥ 6 characters
   - All characters printable (ASCII ≥ 0x20 / 32)
4. **Anti-Debugging**: `ptrace()` prevents GDB analysis
5. **Stack Canary**: Prevents simple buffer overflows

## 🚨 Vulnerability

### CWE-656: Reliance on Security Through Obscurity

The program relies on the **secrecy of the algorithm** rather than cryptographically secure validation.

**Problems with this approach:**

1. **Deterministic**: Same input always produces same output
2. **Reversible**: Algorithm can be reverse-engineered from the binary
3. **No Secret Key**: All constants are hardcoded in the binary
4. **No Server Validation**: All checks happen client-side
5. **Offline Attacks**: Attacker can analyze the binary at leisure

Once the algorithm is understood, we can create a **keygen** that generates valid serials for any login!

## 🎯 The Attack

### Strategy: Reverse Engineering + Keygen

Instead of trying to bypass validation or guess serials, we'll:
1. **Reverse engineer** the serial generation algorithm
2. **Implement** the algorithm in a keygen script
3. **Generate** valid serials for any login we want
4. **Authenticate** and get shell access

### Step 1: Understanding the Algorithm

Let's break down the serial computation:

```python
# Initial seed calculation
seed = (login[3] ^ 0x1337) + 0x5eeded
```

**Why the 4th character?**
- Index 3 (4th character) is chosen arbitrarily as the seed
- XORed with `0x1337` for "randomization"
- Added to base value `0x5eeded`

```python
# Accumulation loop
for each character in login:
    serial += (character ^ serial) % 0x539
```

**What's happening:**
1. XOR current serial with character value
2. Take modulo `0x539` (1337 in decimal - a "leet" number)
3. Add result to serial
4. Repeat for all characters

This creates a **hash-like** function where each character affects the final output.

### Step 2: Algorithm Visualization

```
Login: "helloo"
       ↓↓↓↓↓↓

Step 1: Seed from login[3] = 'l' (0x6c)
┌─────────────────────────────────────┐
│ seed = (0x6c ^ 0x1337) + 0x5eeded   │
│      = 0x135b + 0x5eeded            │
│      = 0x5f0248                     │
└──────────────┬──────────────────────┘
               │
               ▼
Step 2: Process each character
┌─────────────────────────────────────┐
│ i=0: 'h' (0x68)                     │
│   serial += (0x68 ^ 0x5f0248) % 0x539│
│   serial = 0x5f0248 + 0x2c1         │
│   serial = 0x5f0509                 │
├─────────────────────────────────────┤
│ i=1: 'e' (0x65)                     │
│   serial += (0x65 ^ 0x5f0509) % 0x539│
│   serial = 0x5f0509 + 0x1ba         │
│   serial = 0x5f06c3                 │
├─────────────────────────────────────┤
│ ... (continue for all characters)   │
└──────────────┬──────────────────────┘
               │
               ▼
Step 3: Final serial
┌─────────────────────────────────────┐
│ Final value: 6232827                │
└─────────────────────────────────────┘
```

### Step 3: Keygen Implementation

Here's the Python keygen that implements the algorithm:

```python
#!/usr/bin/env python

def generate_serial(login):
    # Remove newline if present
    login = login.rstrip('\n')
    
    # Validation
    if len(login) < 6:
        print("Error: Login must be at least 6 characters")
        return None
    
    for c in login:
        if ord(c) < 0x20:
            print("Error: All characters must be printable")
            return None
    
    # Serial algorithm (exact replica from binary)
    serial = (ord(login[3]) ^ 0x1337) + 0x5eeded
    
    for char in login:
        serial += (ord(char) ^ serial) % 0x539
    
    return serial & 0xFFFFFFFF  # 32-bit unsigned

# Usage
if __name__ == "__main__":
    import sys
    login = sys.argv[1] if len(sys.argv) > 1 else raw_input("Enter login: ")
    serial = generate_serial(login)
    if serial:
        print("Login: %s" % login)
        print("Serial: %d" % serial)
```

### Step 4: Test Cases

Let's verify the keygen with multiple logins:

| Login | 4th Char | Generated Serial | Status |
|-------|----------|------------------|--------|
| `helloo` | `l` (0x6c) | 6232827 | ✅ Tested |
| `aaaaaa` | `a` (0x61) | 6234456 | ✅ Valid |
| `test00` | `t` (0x74) | 6232494 | ✅ Valid |
| `abcdef` | `d` (0x64) | 6232250 | ✅ Valid |

**Calculation for "helloo":**
```
Seed: ('l' ^ 0x1337) + 0x5eeded = (0x6c ^ 0x1337) + 0x5eeded = 0x5f0248

Loop iterations:
  'h': 0x5f0248 + (0x68 ^ 0x5f0248) % 0x539 = 0x5f0509
  'e': 0x5f0509 + (0x65 ^ 0x5f0509) % 0x539 = 0x5f06c3
  'l': 0x5f06c3 + (0x6c ^ 0x5f06c3) % 0x539 = 0x5f0898
  'l': 0x5f0898 + (0x6c ^ 0x5f0898) % 0x539 = 0x5f0a2b
  'o': 0x5f0a2b + (0x6f ^ 0x5f0a2b) % 0x539 = 0x5f0c1c
  'o': 0x5f0c1c + (0x6f ^ 0x5f0c1c) % 0x539 = 0x5f0deb

Final: 0x5f0deb = 6232827 ✅
```

## 💣 Exploit

### Create Keygen Script

Save as `keygen.py`:

```python
#!/usr/bin/env python

def generate_serial(login):
    login = login.rstrip('\n')
    if len(login) < 6:
        return None
    for c in login:
        if ord(c) < 0x20:
            return None
    serial = (ord(login[3]) ^ 0x1337) + 0x5eeded
    for char in login:
        serial += (ord(char) ^ serial) % 0x539
    return serial & 0xFFFFFFFF

if __name__ == "__main__":
    import sys
    login = sys.argv[1] if len(sys.argv) > 1 else raw_input("Enter login: ").strip()
    serial = generate_serial(login)
    if serial:
        print("Login: %s" % login)
        print("Serial: %d" % serial)
```

### Execute

```bash
ssh level06@localhost -p 2222
# Password: h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq

# Generate serial
python keygen.py "helloo"
# Output: Login: helloo, Serial: 6232827

# Authenticate
./level06
```

### Interaction

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
$ whoami
level07
$ cat /home/users/level07/.pass
GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8
```

---

> 💡 **Pro Tip**: The keygen works for ANY login string (≥6 chars, printable). You can use your own creative logins like "soldier", "helldiver", "freedom", etc.

> 💡 **Keygen Philosophy**: This is a classic example of why "security through obscurity" fails. Once an attacker has access to the binary, they can reverse engineer any client-side validation.

> 💡 **Anti-Debugging Bypass**: The `ptrace()` check prevents debugging, but it doesn't matter - we don't need to debug since we reverse-engineered the algorithm and created a keygen!

## 📚 Technical Deep Dive

### The ptrace Anti-Debugging Technique

```c
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
    // Tampering detected!
}
```

**How it works:**
- `PTRACE_TRACEME` tells the kernel "allow my parent to trace me"
- Can only be called **once per process**
- If already being traced (e.g., by GDB), it returns `-1`

**Why it fails to protect:**
1. Doesn't prevent static analysis (Ghidra, IDA, etc.)
2. Can be bypassed with LD_PRELOAD hooks
3. Binary can be patched to skip the check
4. Doesn't protect against reverse engineering

### Understanding the Modulo Operation

```c
(login[i] ^ computed_serial) % 0x539
```

The modulo `0x539` (1337 decimal) serves several purposes:

1. **Bounds the result**: Output is always 0-1336
2. **Non-linear transformation**: Creates complex interactions between characters
3. **Prevents overflow**: Keeps serial from growing too large
4. **Adds "randomness"**: Different characters produce different offsets

However, it's still **deterministic** - same input always produces same output.

### Why This Algorithm is Weak

| Property | Secure System | This System | Impact |
|----------|---------------|-------------|--------|
| **Server-side validation** | ✅ Yes | ❌ No | Can analyze offline |
| **Secret key** | ✅ Yes | ❌ Hardcoded | No secrets to protect |
| **Cryptographic strength** | ✅ Strong | ❌ Weak | Easy to reverse |
| **One-way function** | ✅ Hash | ❌ Deterministic | Can create keygen |
| **Rate limiting** | ✅ Yes | ❌ No | Unlimited attempts |

**A secure system would:**
- Validate serials server-side with a secret key
- Use cryptographic signatures (HMAC, RSA, etc.)
- Implement rate limiting on failed attempts
- Use challenge-response protocols
- Store credentials securely (hashed passwords)

## 🔒 Security Notes

### Vulnerabilities Exploited

1. **[CWE-656](https://cwe.mitre.org/data/definitions/656.html)**: Reliance on Security Through Obscurity
2. **[CWE-798](https://cwe.mitre.org/data/definitions/798.html)**: Use of Hard-coded Credentials
3. **[CWE-327](https://cwe.mitre.org/data/definitions/327.html)**: Use of a Broken or Risky Cryptographic Algorithm

### Real-World Context

This challenge mimics real software licensing systems from the 1990s-2000s:
- Shareware with serial numbers
- Software activation keys
- Game CD keys

Many were cracked the same way:
1. Reverse engineer the validation algorithm
2. Create a keygen
3. Distribute keygens online

**Modern alternatives:**
- Online activation (server-side validation)
- Public-key cryptography (RSA signatures)
- Hardware tokens (FIDO2, YubiKey)
- OAuth/OpenID Connect
- Subscription-based licensing

### Defense Weaknesses

The anti-debugging (`ptrace`) adds minimal security:
- ✅ Stops casual GDB usage
- ❌ Doesn't prevent static analysis
- ❌ Doesn't prevent patching
- ❌ Doesn't prevent keygen creation
- ❌ Can be bypassed with multiple techniques

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8
```

On to level07!
