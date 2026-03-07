#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Intentionally vulnerable functions
void buffer_overflow(const char* input, int len) {
    char buffer[16];  // Small buffer
    memcpy(buffer, input, len);  // No bounds check!
    printf("Data: %s\n", buffer);
}

void format_string(const char* input) {
    printf(input);  // Format string vulnerability!
}

void null_deref(const char* input, int len) {
    char* ptr = NULL;
    if (len > 100) {
        *ptr = 'x';  // Null pointer dereference
    }
}

void integer_overflow(const char* input, int len) {
    if (len > 4) {
        int size = *(int*)input;
        char* buf = malloc(size);  // Integer overflow possible
        if (buf) {
            memcpy(buf, input, len);
            free(buf);
        }
    }
}
