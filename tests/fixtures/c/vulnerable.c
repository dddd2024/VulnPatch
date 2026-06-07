#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Buffer Overflow - strcpy without size check
void copy_user_input(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);  // Dangerous!
}

// Format String Vulnerability - printf with user input
void print_user_data(char *user_input) {
    printf(user_input);  // Dangerous!
}

// Command Injection - system with user input
void run_command(char *cmd) {
    system(cmd);  // Dangerous!
}

// Memory Leak - malloc without free
void allocate_memory() {
    void *ptr = malloc(1024);
    // No free(ptr) - memory leak!
}

// TOCTOU - access then open
void check_and_open(char *filename) {
    if (access(filename, R_OK) == 0) {
        FILE *f = fopen(filename, "r");  // TOCTOU race condition!
        if (f) {
            char buf[256];
            fgets(buf, sizeof(buf), f);
            fclose(f);
        }
    }
}

// Buffer Overflow - gets (always dangerous)
void read_username() {
    char name[32];
    gets(name);  // Always dangerous!
}

// Buffer Overflow - sprintf without bounds
void format_string(char *user_input) {
    char output[128];
    sprintf(output, "Result: %s", user_input);  // Potential overflow
}

int main(int argc, char *argv[]) {
    copy_user_input(argv[1]);
    print_user_data(argv[2]);
    run_command(argv[3]);
    allocate_memory();
    check_and_open(argv[4]);
    read_username();
    return 0;
}
