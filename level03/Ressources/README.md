# 🔐 Level03 - XOR Cipher Cryptanalysis

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Time to break a classic XOR cipher with known plaintext attack!

## 📋 Binary Analysis

### 🔍 Decompiled Code

```c
int decrypt(int key)
{
    char encrypted[17] = {
        0x51, 0x7d, 0x7c, 0x75, 0x60, 0x73, 0x66, 0x67,
        0x7e, 0x73, 0x66, 0x7b, 0x7d, 0x7c, 0x61, 0x33, 0x00
    };
    
    for (int i = 0; i < strlen(encrypted); i++) {
        encrypted[i] ^= key;
    }
    
    if (strcmp(encrypted, "Congratulations!") == 0) {
        system("/bin/sh");
    } else {
        puts("\nInvalid Password");
    }
}

void test(int param_1, int param_2)
{
    int diff = param_2 - param_1;
    
    switch(diff) {
        case 1: ... case 9:
        case 16: ... case 21:
            decrypt(diff);
            break;
        default:
            decrypt(rand());
            break;
    }
}

int main(void)
{
    unsigned int password;
    
    srand(time(NULL));
    
    puts("***********************************");
    puts("*\t\tlevel03\t\t**");
    puts("***********************************");
    printf("Password:");
    
    scanf("%u", &password);
    
    test(password, 0x1337d00d);  // Magic number: 322424845
    
    return 0;
}
```

### Key Observations

1. **XOR Cipher**: Encrypted string is XORed with a key
2. **Known Plaintext**: Target string is `"Congratulations!"` (visible in binary)
3. **Magic Number**: `0x1337d00d` (322424845 in decimal)
4. **Switch Logic**: Only certain difference values are valid
5. **Shell Reward**: Correct decryption spawns `/bin/sh`

## 🚨 Vulnerability

### The Problem: Weak XOR Cipher with Known Plaintext

XOR encryption is **symmetric**: `plaintext ^ key = ciphertext`

This means if we know both the plaintext and ciphertext, we can recover the key:
```
key = plaintext ^ ciphertext
```

Since we know:
- **Encrypted bytes**: `{0x51, 0x7d, 0x7c, 0x75, ...}`
- **Target plaintext**: `"Congratulations!"`

We can calculate the XOR key!

### Switch Statement Logic

The switch statement has specific valid ranges:

```c
diff = 0x1337d00d - password

Valid cases:
  1-9   (0x1-0x9)   → decrypt(diff) directly
  16-21 (0x10-0x15) → decrypt(diff) directly

Invalid cases:
  10-15 (0xa-0xf)   → Fall through to default
  Others            → decrypt(rand()) - unpredictable
```

**Cases 10-15 are missing from the jump table!** They fall through to the default case which uses `rand()`, making the result unpredictable.

## 🎯 The Attack

### Step 1: Derive the XOR Key

Using the XOR property with the first character:

```
Encrypted[0] = 0x51
Target[0]    = 'C' = 0x43

Key = 0x51 ^ 0x43 = 0x12 = 18 (decimal)
```

### Step 2: Verify the Key

Let's verify with all characters:

| Index | Encrypted (hex) | Target | XOR with 0x12 | Result | Match |
|-------|----------------|--------|---------------|--------|-------|
| 0 | 0x51 | 'C' | 0x51 ^ 0x12 | 0x43 ('C') | ✓ |
| 1 | 0x7d | 'o' | 0x7d ^ 0x12 | 0x6f ('o') | ✓ |
| 2 | 0x7c | 'n' | 0x7c ^ 0x12 | 0x6e ('n') | ✓ |
| 3 | 0x75 | 'g' | 0x75 ^ 0x12 | 0x67 ('g') | ✓ |
| 4 | 0x60 | 'r' | 0x60 ^ 0x12 | 0x72 ('r') | ✓ |
| 5 | 0x73 | 'a' | 0x73 ^ 0x12 | 0x61 ('a') | ✓ |
| 6 | 0x66 | 't' | 0x66 ^ 0x12 | 0x74 ('t') | ✓ |
| 7 | 0x67 | 'u' | 0x67 ^ 0x12 | 0x75 ('u') | ✓ |
| 8 | 0x7e | 'l' | 0x7e ^ 0x12 | 0x6c ('l') | ✓ |
| 9 | 0x73 | 'a' | 0x73 ^ 0x12 | 0x61 ('a') | ✓ |
| 10 | 0x66 | 't' | 0x66 ^ 0x12 | 0x74 ('t') | ✓ |
| 11 | 0x7b | 'i' | 0x7b ^ 0x12 | 0x69 ('i') | ✓ |
| 12 | 0x7d | 'o' | 0x7d ^ 0x12 | 0x6f ('o') | ✓ |
| 13 | 0x7c | 'n' | 0x7c ^ 0x12 | 0x6e ('n') | ✓ |
| 14 | 0x61 | 's' | 0x61 ^ 0x12 | 0x73 ('s') | ✓ |
| 15 | 0x33 | '!' | 0x33 ^ 0x12 | 0x21 ('!') | ✓ |

**Perfect match! Key = 18 (0x12)**

### Step 3: Calculate Required Input

We need `diff = 18` in the switch statement:

```
diff = 0x1337d00d - password
18 = 0x1337d00d - password
password = 0x1337d00d - 18
password = 0x1337d00d - 0x12
password = 0x1337cffb
password = 322424827 (decimal)
```

### Execution Flow

```
┌─────────────────────────────────────┐
│ 1. User enters: 322424827           │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 2. test() calculates:               │
│    diff = 0x1337d00d - 322424827    │
│    diff = 18                        │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 3. Switch case 18 (0x12) matches    │
│    Calls: decrypt(18)               │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 4. decrypt() XORs encrypted string  │
│    with key 18                      │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 5. Result: "Congratulations!"       │
│    strcmp() returns 0 (match!)      │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 6. system("/bin/sh") spawns shell   │
└─────────────────────────────────────┘
```

## 💣 Exploit

### Connect and Execute

```bash
ssh level03@localhost -p 2222
# Password: Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H

./level03
# Password: 322424827
```

### Output

```
***********************************
*               level03         **
***********************************
Password:322424827
$ whoami
level04
$ cat /home/users/level04/.pass
kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
```

### Why This Works

The magic number `0x1337d00d` (1337 d00d / "leet dude") is a constant. By choosing our input carefully, we control the `diff` value that gets passed to `decrypt()`. Since we know the XOR key must be 18 to decrypt the string correctly, we calculate the input that produces `diff = 18`.

---

> 💡 **Pro Tip**: XOR encryption is **not secure** when the attacker knows the plaintext! This is called a "known-plaintext attack". Modern encryption uses complex algorithms like AES, ChaCha20, or RSA that resist this type of analysis.

> 💡 **Crypto Note**: Single-byte XOR ciphers are especially weak. Even without knowing the plaintext, frequency analysis can break them. Always use cryptographically secure algorithms with proper key management!

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
```

On to level04!
