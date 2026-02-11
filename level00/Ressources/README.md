# Level00 - Hardcoded Password

![Helldivers Salute](https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExaW03Z2o0bWdvdGxocG9xOWlsNGdhZXR0Y3E3cmFjcWI5MzI3OGo3dSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/YN1eB6slBDeNHr1gjs/giphy.gif)

Welcome to OverRide! Level00 is a warm-up challenge that introduces the concept of hardcoded credentials - a common security vulnerability in real-world applications.

## Binary Analysis

### Decompiled Code

```c
int main(void)
{
    int password;
    
    puts("***********************************");
    puts("* \t     -Level00 -\t\t  *");
    puts("***********************************");
    printf("Password:");
    
    scanf("%d", &password);
    
    if (password == 0x149c) {
        puts("\nAuthenticated!");
        system("/bin/sh");
    } else {
        puts("\nInvalid Password!");
    }
    
    return 0;
}
```

### Key Observations

1. **Input Type**: The program uses `scanf("%d", ...)` - expecting a decimal integer
2. **Comparison**: Checks if input equals `0x149c` (hexadecimal)
3. **Reward**: Spawns a shell via `system("/bin/sh")` on success
4. **SUID Bit**: The binary runs with level01 privileges

## Vulnerability

### The Problem: Hardcoded Credentials

The password is hardcoded directly in the binary as a hexadecimal constant `0x149c`. This means:

- Anyone with access to the binary can reverse-engineer it
- The password cannot be changed without recompiling
- It's visible in disassembly/decompilation tools like Ghidra, IDA, or objdump

### Finding the Password

In Ghidra, simply hover over the hexadecimal constant `0x149c` and it will display the decimal value: **5276**

That's it! Ghidra does the conversion for you.

## How the Exploit Works

### Step-by-Step Execution Flow

```
┌─────────────────────────────────────┐
│  1. Binary runs with SUID bit       │
│     (level01 privileges)            │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  2. Prompt for password             │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  3. User enters: 5276               │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  4. Comparison: 5276 == 0x149c?     │
│     YES ✓                           │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  5. system("/bin/sh") executes      │
│     Shell inherits level01 privs    │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  6. Read /home/users/level01/.pass  │
│     Get flag for next level         │
└─────────────────────────────────────┘
```

## Exploit

### Connect and Execute

```bash
ssh level00@localhost -p 2222
# Password: level00

./level00
# Enter: 5276
```

### Output

```
***********************************
*            -Level00 -           *
***********************************
Password:5276

Authenticated!
$ whoami
level01
$ cat /home/users/level01/.pass
uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL
```

---

> **Pro Tip**: Hardcoded credentials are a [CWE-798](https://cwe.mitre.org/data/definitions/798.html) vulnerability. Always store secrets in environment variables, secure vaults (like HashiCorp Vault), or encrypted configuration files.

> **Security Note**: Modern authentication systems use:
> - Hashed passwords with salt (bcrypt, Argon2)
> - Multi-factor authentication (MFA)
> - Key derivation functions (PBKDF2, scrypt)
> - Never store passwords in plaintext or as reversible constants

## Victory!

![Helldivers Victory](https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExaTczOXJ1cDdkOWJ2c2d3MHJxN3U2ZjBsaWUwbzUydmtoNGEwMXNtNCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/mXnO9IiWWarkI/giphy.gif)

**Flag captured!**

```
uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL
```

On to level01!
