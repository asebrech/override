#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Function prototypes
void clear_stdin(void);
unsigned int get_unum(void);
int read_number(unsigned int *data);
int store_number(unsigned int *data);

// Clears the input buffer to prevent residual input from interfering
void clear_stdin(void)
{
    int c;
    do {
        c = getchar();
    } while (c != '\n' && c != -1);
}

// Reads an unsigned integer from standard input
unsigned int get_unum(void)
{
    unsigned int input = 0;
    
    fflush(stdout);
    scanf("%u", &input);
    clear_stdin();
    
    return input;
}

// VULNERABILITY: Out-of-bounds read - no bounds checking on index
// Allows reading arbitrary memory locations relative to the data array
int read_number(unsigned int *data)
{
    unsigned int index;
    
    printf(" Index: ");
    index = get_unum();
    
    // Directly accesses data[index] without validating index < 100
    printf(" Number at data[%u] is %u\n", index, data[index]);
    
    return 0;
}

// VULNERABILITY: Integer overflow + out-of-bounds write
// CWE-787: Out-of-Bounds Write
// CWE-190: Integer Overflow or Wraparound
int store_number(unsigned int *data)
{
    unsigned int number;
    unsigned int index;
    
    printf(" Number: ");
    number = get_unum();
    printf(" Index: ");
    index = get_unum();
    
    // Security checks (both are bypassable):
    // 1. Block indices divisible by 3 (can be bypassed via integer overflow)
    // 2. Block numbers starting with 0xb7 (outdated libc protection)
    if ((index % 3 == 0) || (number >> 24 == 0xb7)) {
        puts(" *** ERROR! ***");
        puts("   This index is reserved for wil!");
        puts(" *** ERROR! ***");
        return 1;
    }
    
    // CRITICAL FLAW: No upper bound checking
    // Allows arbitrary memory write at: data_base_address + (index * 4)
    data[index] = number;
    
    return 0;
}

int main(int argc, char **argv, char **envp)
{
    char command[20];
    unsigned int data[100];  // Array to store 100 integers (400 bytes)
    int status = 0;
    
    // Initialize data storage to zero
    memset(data, 0, sizeof(data));
    
    // Security theater: Zero out argv and envp to prevent environment-based exploits
    // This prevents using environment variables for shellcode injection
    for (char **arg = argv; *arg != NULL; arg++) {
        memset(*arg, 0, strlen(*arg));
    }
    for (char **env = envp; *env != NULL; env++) {
        memset(*env, 0, strlen(*env));
    }
    
    // Display welcome banner and available commands
    puts("----------------------------------------------------");
    puts("  Welcome to wil's crappy number storage service!   ");
    puts("----------------------------------------------------");
    puts(" Commands:                                          ");
    puts("    store - store a number into the data storage    ");
    puts("    read  - read a number from the data storage     ");
    puts("    quit  - exit the program                        ");
    puts("----------------------------------------------------");
    puts("   wil has reserved some storage :>                ");
    puts("----------------------------------------------------");
    
    // Main command loop
    while (true) {
        printf("Input command: ");
        status = 1;
        
        // Read command from user
        if (fgets(command, 20, stdin) == NULL)
            break;
        
        // Remove trailing newline
        command[strcspn(command, "\n")] = '\0';
        
        // Process commands
        if (strcmp(command, "store") == 0) {
            status = store_number(data);
        }
        else if (strcmp(command, "read") == 0) {
            status = read_number(data);
        }
        else if (strcmp(command, "quit") == 0) {
            return 0;
        }
        
        // Display command result
        if (status == 0) {
            printf(" Completed %s command successfully\n", command);
        } else {
            printf(" Failed to do %s command\n", command);
        }
        
        // Clear command buffer
        memset(command, 0, sizeof(command));
    }
    
    return 0;
}
