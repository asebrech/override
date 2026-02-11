/*
 * OverRide - Level03
 * 
 * Vulnerability: XOR Cipher with Known Plaintext + Switch Statement Logic
 * 
 * This binary uses a simple XOR cipher to encrypt a validation string.
 * By analyzing the encrypted bytes and knowing the target plaintext
 * ("Congratulations!"), we can derive the XOR key and calculate the
 * required input password.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void clear_stdin(void)
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

unsigned int get_unum(void)
{
    unsigned int num = 0;
    fflush(stdout);
    scanf("%u", &num);
    clear_stdin();
    return num;
}

void prog_timeout(void)
{
    // System call to exit
    exit(1);
}

int decrypt(int key)
{
    // Encrypted string (XOR cipher)
    char encrypted[17] = {
        0x51, 0x7d, 0x7c, 0x75, 0x60, 0x73, 0x66, 0x67,
        0x7e, 0x73, 0x66, 0x7b, 0x7d, 0x7c, 0x61, 0x33, 0x00
    };
    
    // XOR each byte with the key
    for (int i = 0; i < strlen(encrypted); i++) {
        encrypted[i] ^= key;
    }
    
    // Compare decrypted string with target
    if (strcmp(encrypted, "Congratulations!") == 0) {
        system("/bin/sh");
    } else {
        puts("\nInvalid Password");
    }
    
    return 0;
}

void test(int param_1, int param_2)
{
    int diff = param_2 - param_1;
    
    // Switch statement based on difference
    // Valid cases: 1-9 and 16-21 (0x10-0x15)
    // Cases 10-15 (0xa-0xf) fall through to default
    switch(diff) {
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 16:  // 0x10
        case 17:  // 0x11
        case 18:  // 0x12 - The correct key!
        case 19:  // 0x13
        case 20:  // 0x14
        case 21:  // 0x15
            decrypt(diff);
            break;
        default:
            // Cases 10-15 and others fall here
            decrypt(rand());
            break;
    }
}

int main(void)
{
    unsigned int password;
    
    // Seed random number generator
    srand(time(NULL));
    
    puts("***********************************");
    puts("*\t\tlevel03\t\t**");
    puts("***********************************");
    printf("Password:");
    
    scanf("%u", &password);
    
    // Call test with password and magic number
    test(password, 0x1337d00d);  // 322424845 in decimal
    
    return 0;
}
