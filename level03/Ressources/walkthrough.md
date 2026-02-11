# Walkthrough

## 1. Download the binary

```bash
scp -P 2222 level03@localhost:~/level03 .
# Password: Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
```

## 2. Analyze with Ghidra

Open the binary in Ghidra and examine the `main`, `test`, and `decrypt` functions.

## 3. Understand the program flow

**main():**
- Seeds random number generator
- Prompts for password input
- Calls `test(password, 0x1337d00d)`

**test(password, 0x1337d00d):**
- Calculates: `diff = 0x1337d00d - password`
- Switch statement on `diff`
- Valid cases (1-9, 16-21) call `decrypt(diff)`
- Invalid cases (10-15, others) call `decrypt(rand())`

**decrypt(key):**
- Has encrypted string: `{0x51, 0x7d, 0x7c, 0x75, 0x60, 0x73, 0x66, 0x67, 0x7e, 0x73, 0x66, 0x7b, 0x7d, 0x7c, 0x61, 0x33, 0x00}`
- XORs each byte with `key`
- Compares result to `"Congratulations!"`
- If match: spawns shell

## 4. Find the XOR key

The encrypted string must XOR with the key to produce `"Congratulations!"`.

**Target plaintext:** `"Congratulations!"`

Using XOR property: `encrypted[0] ^ key = plaintext[0]`

Therefore: `key = encrypted[0] ^ plaintext[0]`

```
key = 0x51 ^ 'C'
key = 0x51 ^ 0x43
key = 0x12
key = 18 (decimal)
```

## 5. Verify the key

Check multiple characters:

| Index | Encrypted | Target | XOR Result |
|-------|-----------|--------|------------|
| 0 | 0x51 | 'C' (0x43) | 0x51 ^ 0x12 = 0x43 ✓ |
| 1 | 0x7d | 'o' (0x6f) | 0x7d ^ 0x12 = 0x6f ✓ |
| 2 | 0x7c | 'n' (0x6e) | 0x7c ^ 0x12 = 0x6e ✓ |

**Key = 18 is correct!**

## 6. Calculate the required input

From `test()`: `diff = 0x1337d00d - password`

We need `diff = 18`:

```
password = 0x1337d00d - 18
password = 0x1337d00d - 0x12
password = 0x1337cffb
password = 322424827 (decimal)
```

## 7. Connect to the VM

```bash
ssh level03@localhost -p 2222
# Password: Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
```

## 8. Execute the exploit

```bash
./level03
# Password: 322424827
```

**Output:**
```
***********************************
*               level03         **
***********************************
Password:322424827
$
```

## 9. Get the flag

```bash
cat /home/users/level04/.pass
```

## 10. Flag

```
kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
```
