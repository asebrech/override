#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

// VULNERABILITY: Format String in log_wrapper
// CWE-134: Uncontrolled Format String
void log_wrapper(FILE *log_file, char *prefix, char *msg)
{
    char buffer[264];
    
    // Copy prefix to buffer
    strcpy(buffer, prefix);
    
    // CRITICAL FLAW: msg is used as format string!
    // If msg contains format specifiers like %p, %x, %s, they will be interpreted
    snprintf(buffer + strlen(buffer), 254 - strlen(buffer), msg);
    
    // Remove trailing newline if present
    buffer[strcspn(buffer, "\n")] = '\0';
    
    // Write to log file
    fprintf(log_file, "LOG: %s\n", buffer);
}

int main(int argc, char **argv)
{
    FILE *log_fp;
    FILE *source_fp;
    int backup_fd;
    int char_read;
    char backup_path[104];
    char c;
    
    // Check command line arguments
    if (argc != 2) {
        printf("Usage: %s filename\n", argv[0]);
    }
    
    // VULNERABILITY: Uses relative path "./backups/"
    // CWE-426: Untrusted Search Path
    // The backup directory is relative to current working directory
    // Attacker can control where backups are written by changing CWD
    
    // Open log file (also relative path)
    log_fp = fopen("./backups/.log", "w");
    if (log_fp == NULL) {
        printf("ERROR: Failed to open %s\n", "./backups/.log");
        exit(1);
    }
    
    // Log the start of backup operation
    // NOTE: argv[1] is passed to log_wrapper as format string (vulnerable!)
    log_wrapper(log_fp, "Starting back up: ", argv[1]);
    
    // Open source file for reading
    // IMPORTANT: If binary has SUID bit, it can read files owned by the SUID user
    source_fp = fopen(argv[1], "r");
    if (source_fp == NULL) {
        printf("ERROR: Failed to open %s\n", argv[1]);
        exit(1);
    }
    
    // Construct backup path: "./backups/" + argv[1]
    // Example: argv[1] = "/etc/passwd" → backup_path = "./backups//etc/passwd"
    strncpy(backup_path, "./backups/", 11);
    strncat(backup_path, argv[1], 99 - strlen(backup_path));
    
    // Create backup file with specific flags:
    // O_WRONLY: Write-only
    // O_CREAT: Create if doesn't exist
    // O_EXCL: Fail if file already exists (prevents overwriting)
    // Permissions: 0660 (rw-rw----)
    backup_fd = open(backup_path, O_WRONLY | O_CREAT | O_EXCL, 0660);
    if (backup_fd < 0) {
        printf("ERROR: Failed to open %s%s\n", "./backups/", argv[1]);
        exit(1);
    }
    
    // Copy file byte-by-byte from source to backup
    while ((char_read = fgetc(source_fp)) != EOF) {
        c = (char)char_read;
        write(backup_fd, &c, 1);
    }
    
    // Log completion
    log_wrapper(log_fp, "Finished back up ", argv[1]);
    
    // Cleanup
    fclose(source_fp);
    close(backup_fd);
    
    return 0;
}
