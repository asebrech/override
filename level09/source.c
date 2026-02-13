#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Structure layout on stack in handle_msg function:
 * 
 * Memory Layout (from low to high addresses):
 * +-----------------+  <- RBP - 0xc0 (local_c8)
 * | message[140]    |  Offset: 0
 * +-----------------+  <- RBP - 0x8c + 140 = RBP - 0x34
 * | username[40]    |  Offset: 140 (0x8c)
 * +-----------------+  <- RBP - 0x8c + 180 = RBP - 0x14
 * | len (4 bytes)   |  Offset: 180 (0xb4)
 * +-----------------+  <- RBP - 0x8c + 184 = RBP - 0xc
 * | (padding)       |
 * +-----------------+  <- RBP
 * | Saved RBP       |  8 bytes
 * +-----------------+  <- RBP + 8
 * | Saved RIP       |  8 bytes (Return address - TARGET!)
 * +-----------------+
 */
struct s_data {
    char message[140];  // Offset 0
    char username[40];  // Offset 140 (0x8c)
    int len;           // Offset 180 (0xb4)
};

// VULNERABILITY 1: Off-by-One Error (CWE-193)
// This function writes one byte past the username buffer
void set_username(struct s_data *data) {
    char input[140];
    int i;

    // Initialize local buffer to zero
    memset(input, 0, 140);

    puts(">: Enter your username");
    printf(">>: ");
    
    // Read up to 128 bytes (0x80)
    fgets(input, 128, stdin);

    /* CRITICAL FLAW: Off-by-One Error
     * Loop iterates up to 41 (0x29) but username buffer is only 40 bytes!
     * The 41st byte (index 40) overwrites the first byte of data->len
     * 
     * Correct condition should be: i < 40 (or i <= 39)
     * Current condition: i < 41 (allows i=0 to i=40, which is 41 iterations)
     */
    for (i = 0; i < 41 && input[i] != '\0'; i++) {
        data->username[i] = input[i];
    }

    printf(">: Welcome, %s", data->username);
}

// VULNERABILITY 2: Buffer Overflow (CWE-120)
// Uses the corrupted 'len' value from off-by-one error
void set_msg(struct s_data *data) {
    char input[1024];

    // Initialize local buffer to zero (loop of 128 * 8 bytes)
    memset(input, 0, 1024);

    puts(">: Msg @Unix-Dude");
    printf(">>: ");
    
    // Read up to 1024 bytes (0x400)
    fgets(input, 1024, stdin);

    /* CRITICAL FLAW: Unchecked Buffer Copy
     * strncpy uses data->len which was corrupted by set_username!
     * 
     * Normal value: len = 140 (0x8c)
     * After corruption: len = 255 (0xff) if we write 0xff at byte 40
     * 
     * This allows copying 255 bytes into a 140-byte buffer!
     * The overflow can reach past message buffer into:
     * - username (already filled)
     * - len (already corrupted)
     * - saved RBP (8 bytes)
     * - saved RIP (8 bytes) <- OUR TARGET!
     */
    strncpy(data->message, input, (size_t)data->len);
}

void handle_msg() {
    struct s_data data;

    // Initialize structure on stack
    memset(data.message, 0, 140);
    memset(data.username, 0, 40);
    data.len = 140; // 0x8c in hexadecimal

    // First, set username (corrupts len via off-by-one)
    set_username(&data);
    
    // Then, set message (overflows using corrupted len)
    set_msg(&data);

    puts(">: Msg sent!");
}

int main(void) {
    puts(
        "--------------------------------------------\n"
        "|   ~Welcome to l33t-m$n ~    v1337        |\n"
        "--------------------------------------------"
    );

    handle_msg();

    return 0;
}

/* HIDDEN FUNCTION: Secret Backdoor (Never called in normal execution!)
 * 
 * This function is compiled into the binary but never called.
 * It provides arbitrary command execution via system().
 * 
 * To exploit:
 * 1. Overflow the buffer to overwrite saved RIP
 * 2. Point RIP to address of secret_backdoor
 * 3. When handle_msg returns, execution jumps here
 * 4. This function reads our command and executes it
 * 
 * Address (example with PIE): 0x55555555488c
 * Find dynamically with: (gdb) p secret_backdoor
 */
void secret_backdoor(void)
{
    char command_buffer[128];
  
    // Read up to 128 bytes (0x80) from stdin
    fgets(command_buffer, 128, stdin);
    
    // Execute the string as a system command
    // DANGER: Arbitrary command execution!
    system(command_buffer);
    
    return;
}
