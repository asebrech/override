/*
 * OverRide - Level05
 * 
 * Architecture: x86 (32-bit)
 * Vulnerability: Format String + Character Transformation
 * 
 * This binary reads user input, converts uppercase letters (A-Z) to lowercase (a-z),
 * then passes the buffer directly to printf() without a format specifier.
 * 
 * The uppercase-to-lowercase conversion prevents traditional shellcode injection
 * (shellcode bytes in the 0x41-0x5A range get corrupted). The solution is to
 * store shellcode in an environment variable and use format string writes to
 * overwrite a GOT entry to redirect execution.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char buffer[100];
    unsigned int i;
    
    // Read user input (100 bytes max)
    fgets(buffer, 100, stdin);
    
    // Convert uppercase letters to lowercase
    for (i = 0; i < strlen(buffer); i++) {
        // Check if character is uppercase (ASCII 0x41-0x5A / 'A'-'Z')
        if (buffer[i] > '@' && buffer[i] < '[') {
            // XOR with 0x20 converts uppercase to lowercase
            // 'A' (0x41) ^ 0x20 = 'a' (0x61)
            buffer[i] ^= 0x20;
        }
    }
    
    // FORMAT STRING VULNERABILITY!
    // Buffer passed directly to printf without format specifier
    printf(buffer);
    
    // Exit cleanly
    exit(0);
}
