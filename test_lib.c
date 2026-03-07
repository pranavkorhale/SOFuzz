#include <stdio.h>
#include <string.h>

void parse_data(const char* data, int len) {
    char buffer[64];
    if (len > 0 && data != NULL) {
        memcpy(buffer, data, len);
        printf("Parsed %d bytes\n", len);
    }
}

void process_input(const char* input) {
    if (input != NULL) {
        printf("Processing: %s\n", input);
    }
}

int calculate(int a, int b) {
    return a + b;
}
