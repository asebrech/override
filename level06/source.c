/*
 * OverRide - Level06
 * 
 * Architecture: x86 (32-bit)
 * Vulnerability: Weak Serial Validation Algorithm
 * 
 * This binary implements a login/serial validation system where the serial
 * is computed from the login string using a deterministic algorithm. By
 * reverse engineering the algorithm, we can create a keygen that generates
 * valid serials for any login.
 * 
 * The program also includes anti-debugging via ptrace() to prevent analysis,
 * but this can be bypassed by simply running the keygen outside of a debugger.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

int auth(char *login, unsigned int serial)
{
    size_t len;
    unsigned int computed_serial;
    int i;
    
    // Remove trailing newline from login
    login[strcspn(login, "\n")] = '\0';
    
    // Get login length (max 32 chars)
    len = strnlen(login, 0x20);
    
    // Validation: Login must be at least 6 characters
    if (len < 6) {
        return 1;  // Authentication failed
    }
    
    // Anti-debugging check using ptrace
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        puts("\x1b[32m.---------------------------.");
        puts("\x1b[31m| !! TAMPERING DETECTED !!  |");
        puts("\x1b[32m\'---------------------------\'");
        return 1;  // Authentication failed
    }
    
    // Validation: All characters must be printable (ASCII >= 0x20)
    for (i = 0; i < len; i++) {
        if (login[i] < ' ') {
            return 1;  // Authentication failed
        }
    }
    
    // Serial generation algorithm:
    // Start with the 4th character XORed with magic value
    computed_serial = (login[3] ^ 0x1337) + 0x5eeded;
    
    // For each character in the login
    for (i = 0; i < len; i++) {
        // XOR character with current serial, take modulo 0x539, and add to serial
        computed_serial += (login[i] ^ computed_serial) % 0x539;
    }
    
    // Compare user-provided serial with computed serial
    if (serial == computed_serial) {
        return 0;  // Authentication successful!
    } else {
        return 1;  // Authentication failed
    }
}

int main(void)
{
    char login[32];
    unsigned int serial;
    int auth_result;
    
    puts("***********************************");
    puts("*\t\tlevel06\t\t  *");
    puts("***********************************");
    
    // Get login
    printf("-> Enter Login: ");
    fgets(login, 0x20, stdin);
    
    puts("***********************************");
    puts("***** NEW ACCOUNT DETECTED ********");
    puts("***********************************");
    
    // Get serial
    printf("-> Enter Serial: ");
    scanf("%u", &serial);
    
    // Validate login/serial pair
    auth_result = auth(login, serial);
    
    if (auth_result == 0) {
        puts("Authenticated!");
        system("/bin/sh");
        return 0;
    }
    
    return 1;
}
