# Walkthrough

## 1. Download the binary

```bash
scp -P 2222 level00@localhost:~/level00 .
# Password: level00
```

## 2. Analyze with Ghidra

Open the binary in Ghidra and examine the main function.

## 3. Find the password

The binary compares input against `0x149c`. 

In Ghidra, hover over `0x149c` to see the decimal value: **5276**

## 4. Connect to the VM

```bash
ssh level00@localhost -p 2222
# Password: level00
```

## 5. Execute the exploit

```bash
./level00
# Enter: 5276
```

## 6. Get the flag

```bash
cat /home/users/level01/.pass
```

## 7. Flag

```
uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL
```
