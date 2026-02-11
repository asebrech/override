/*
 * OverRide - Level00
 * 
 * Vulnerability: Hardcoded Password Comparison
 * 
 * This binary compares user input against a hardcoded value (0x149c = 5276).
 * If the input matches, it spawns a shell with elevated privileges.
 */

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int password;
    
    puts("***********************************");
    puts("* \t     -Level00 -\t\t  *");
    puts("***********************************");
    printf("Password:");
    
    scanf("%d", &password);
    
    // Hardcoded password check: 0x149c = 5276 in decimal
    if (password == 0x149c) {
        puts("\nAuthenticated!");
        system("/bin/sh");  // Spawns shell with level01 privileges (SUID)
    } else {
        puts("\nInvalid Password!");
    }
    
    return 0;
}
