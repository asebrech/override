/*
 * OverRide - Level02
 * 
 * Architecture: x86_64 (64-bit)
 * Vulnerability: Format String
 * 
 * This binary reads the password for level03 into a stack buffer,
 * then prompts for username/password. If authentication fails,
 * it prints the username directly to printf() without a format specifier.
 * 
 * This format string vulnerability allows us to read stack memory,
 * leaking the level03 password that was loaded earlier.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char username[100];      // At [RBP - 0x70]
    char password_input[112]; // At [RBP - 0x110]
    char password_file[48];   // At [RBP - 0xa0] - Stores level03's password!
    int bytes_read;
    FILE *fp;
    
    // Initialize buffers
    memset(username, 0, 100);
    memset(password_input, 0, 112);
    memset(password_file, 0, 48);
    
    fp = NULL;
    bytes_read = 0;
    
    // Read the password for level03 into stack buffer
    fp = fopen("/home/users/level03/.pass", "r");
    if (fp == NULL) {
        fwrite("ERROR: failed to open password file\n", 1, 0x24, stderr);
        exit(1);
    }
    
    // Read 41 bytes (0x29) from password file
    bytes_read = fread(password_file, 1, 0x29, fp);
    
    // Remove newline
    password_file[strcspn(password_file, "\n")] = '\0';
    
    if (bytes_read != 0x29) {
        fwrite("ERROR: failed to read password file\n", 1, 0x24, stderr);
        fwrite("ERROR: failed to read password file\n", 1, 0x24, stderr);
        exit(1);
    }
    
    fclose(fp);
    
    // Display login prompt
    puts("===== [ Secure Access System v1.0 ] =====");
    puts("/***************************************\\");
    puts("| You must login to access this system. |");
    puts("\\**************************************/");
    
    // Get username
    printf("--[ Username: ");
    fgets(username, 100, stdin);
    username[strcspn(username, "\n")] = '\0';
    
    // Get password
    printf("--[ Password: ");
    fgets(password_input, 100, stdin);
    password_input[strcspn(password_input, "\n")] = '\0';
    
    puts("*****************************************");
    
    // Compare passwords
    if (strncmp(password_file, password_input, 0x29) == 0) {
        printf("Greetings, %s!\n", username);
        system("/bin/sh");
        return 0;
    }
    
    // FORMAT STRING VULNERABILITY!
    // Username is passed directly to printf without format specifier
    printf(username);
    puts(" does not have access!");
    exit(1);
}
