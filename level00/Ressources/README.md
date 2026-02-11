# 🔐 Level00 - Hardcoded Password

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Welcome to OverRide! Time to crack your first challenge!

## 📋 Binary Analysis

### 🔍 Decompiled Code

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

## 🚨 Vulnerability

### The Problem: Hardcoded Credentials

The password is hardcoded directly in the binary as a hexadecimal constant `0x149c`. This means:

- Anyone with access to the binary can reverse-engineer it
- The password cannot be changed without recompiling
- It's visible in disassembly/decompilation tools like Ghidra, IDA, or objdump

### Finding the Password

In Ghidra, simply hover over the hexadecimal constant `0x149c` and it will display the decimal value: **5276**

That's it! Ghidra does the conversion for you.

## 🎯 The Attack

Simple and straightforward:

1. **Binary runs with SUID** - Inherits level01 privileges
2. **User enters: 5276** - The magic number
3. **Comparison succeeds** - `5276 == 0x149c` ✓
4. **Shell spawned** - `system("/bin/sh")` with level01 privileges
5. **Flag retrieved** - Read `/home/users/level01/.pass`

## 💣 Exploit

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

> 💡 **Pro Tip**: Hardcoded credentials are a [CWE-798](https://cwe.mitre.org/data/definitions/798.html) vulnerability. Always use secure credential storage like environment variables or vaults!

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL
```

On to level01!
