/*
 * OverRide - Level01
 * 
 * Vulnerability: Buffer Overflow + Logic Bug
 * 
 * This binary has two critical issues:
 * 1. Logic bug: Password check always fails due to (x == 0) || (x != 0) always being true
 * 2. Buffer overflow: fgets reads 100 bytes into a 64-byte buffer
 * 
 * The exploit uses the username buffer (global variable) to store shellcode,
 * then overflows the password buffer to redirect execution to the shellcode.
 */

#include <stdio.h>
#include <string.h>

#define USERNAME_SIZE 256

// Global buffer at address 0x0804a040
char a_user_name[USERNAME_SIZE];

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
    char password[64];  // Buffer at [ESP + 0x1c]
    int result;
    
    // Initialize password buffer to zero
    memset(password, 0, 64);
    
    result = 0;
    
    puts("********* ADMIN LOGIN PROMPT *********");
    printf("Enter Username: ");
    
    // Read 256 bytes into global buffer (safe)
    fgets(a_user_name, 0x100, stdin);
    
    result = verify_user_name();
    
    if (result == 0) {
        puts("Enter Password: ");
        
        // VULNERABILITY: Reads 100 bytes into 64-byte buffer!
        fgets(password, 100, stdin);
        
        result = verify_user_pass(password);
        
        // LOGIC BUG: This condition is ALWAYS TRUE!
        // (result == 0) || (result != 0) covers all possible values
        if ((result == 0) || (result != 0)) {
            puts("nope, incorrect password...\n");
            return 1;
        }
        else {
            // This code is unreachable due to logic bug
            return 0;
        }
    }
    else {
        puts("nope, incorrect username...\n");
        return 1;
    }
}
