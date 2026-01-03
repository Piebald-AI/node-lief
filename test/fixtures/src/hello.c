/*
 * Simple test binary for node-lief tests
 * Cross-compile with Zig for all platforms
 */

#include <stdio.h>

/* Some global data to create .data section */
int global_counter = 42;
const char* message = "Hello from LIEF test binary!";

/* A helper function to ensure we have symbols */
int helper_function(int x) {
    return x * 2 + global_counter;
}

/* Another function for more symbols */
void print_message(void) {
    printf("%s\n", message);
}

int main(int argc, char** argv) {
    int result;
    
    print_message();
    result = helper_function(argc);
    printf("Result: %d\n", result);
    
    return 0;
}
