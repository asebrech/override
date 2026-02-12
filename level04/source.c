/*
 * OverRide - Level04
 * 
 * Architecture: x86 (32-bit)
 * Vulnerability: Buffer Overflow + Anti-Debugging (ptrace)
 * 
 * This binary forks a child process that is traced by the parent.
 * The child process has a buffer overflow vulnerability via gets().
 * The parent monitors for execve syscalls and kills the child if detected.
 * 
 * The exploit uses ret2libc to call system() directly, bypassing the
 * execve detection since system() is a library function call, not a direct syscall.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>

int main(void)
{
    char buffer[128];       // Buffer at ESP + 0x20
    pid_t child_pid;
    int status;
    long syscall_number;
    
    // Fork a child process
    child_pid = fork();
    
    // Initialize buffer to zero
    memset(buffer, 0, sizeof(buffer));
    status = 0;
    
    if (child_pid == 0) {
        // CHILD PROCESS
        
        // Set parent death signal - child dies if parent dies
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        
        // Allow parent to trace this process
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        
        // Prompt for input
        puts("Give me some shellcode, k");
        
        // VULNERABILITY: gets() has no bounds checking!
        // Buffer is 128 bytes, but gets() can write unlimited data
        gets(buffer);
    }
    else {
        // PARENT PROCESS - Traces the child
        
        do {
            // Wait for child to change state
            wait(&status);
            
            // Check if child exited normally or was terminated
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                puts("child is exiting...");
                return 0;
            }
            
            // Read the syscall number from child's registers
            // 0x2c (44) is the offset of orig_eax in user struct
            syscall_number = ptrace(PTRACE_PEEKUSER, child_pid, 44, 0);
            
        } while (syscall_number != 11);  // 11 = execve syscall
        
        // If execve detected, kill the child
        puts("no exec() for you");
        kill(child_pid, SIGKILL);
    }
    
    return 0;
}
