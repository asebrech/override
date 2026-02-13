# 🔐 OverRide - Binary Exploitation Challenge

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Complete documentation and walkthroughs for all 10 levels of the OverRide binary exploitation CTF challenge.

## 📋 About

OverRide is a progressive binary exploitation challenge consisting of 10 levels. Each level requires exploiting a vulnerability to obtain a password for the next level.

**Access:**
```bash
ssh levelXX@localhost -p 2222
# Use the password from the previous level's flag
```

## 🎯 Challenge Levels

| Level | Vulnerability Type | Status |
|-------|-------------------|--------|
| [00](level00/) | Hardcoded Password | ✅ |
| [01](level01/) | Buffer Overflow + Logic Bug | ✅ |
| [02](level02/) | Format String Leak | ✅ |
| [03](level03/) | XOR Cipher | ✅ |
| [04](level04/) | ret2libc | ✅ |
| [05](level05/) | Format String + GOT Overwrite | ✅ |
| [06](level06/) | Serial Keygen | ✅ |
| [07](level07/) | Integer Overflow + ret2libc | ✅ |
| [08](level08/) | SUID Path Manipulation | ✅ |
| [09](level09/) | Off-by-One + Buffer Overflow | ✅ |

## 📚 Repository Structure

```
levelXX/
├── flag                    # Password for next level
├── source.c               # Reconstructed source with annotations
└── Ressources/
    ├── walkthrough.md     # Step-by-step guide
    └── README.md          # Detailed documentation
```

## 🛠️ Tools

**Required:**
- [Ghidra](https://ghidra-sre.org/) - Reverse engineering
- [GDB](https://www.gnu.org/software/gdb/) - Debugging
- Python - Exploit scripting
- SSH client - VM access

## 🚀 Quick Start

1. **Access the level:**
   ```bash
   ssh level00@localhost -p 2222
   ```

2. **Download the binary:**
   ```bash
   scp -P 2222 level00@localhost:~/level00 .
   ```

3. **Analyze with Ghidra and follow the documentation**

## 🎓 Vulnerability Types Covered

| Vulnerability | CWE | Levels |
|--------------|-----|--------|
| Buffer Overflow | CWE-120, CWE-787 | 01, 04, 07, 09 |
| Format String | CWE-134 | 02, 05, 08 |
| Integer Overflow | CWE-190 | 07 |
| Off-by-One Error | CWE-193 | 09 |
| Path Manipulation | CWE-426 | 08 |
| Logic Bugs | Various | 00, 01, 03, 06 |

## 🎉 Congratulations!

![Mission Success](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

Complete OverRide documentation for all 10 levels. Happy hacking! 🚀

---

*Repository maintained for educational purposes.*
