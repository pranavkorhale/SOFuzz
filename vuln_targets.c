#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 1. Stack Buffer Overflow
__attribute__((visibility("default")))
void vuln_stack_overflow(const char* data, size_t len) {
    char buffer[32];
    // VULNERABILITY: No bound check on 'len', causing stack overflow
    if (len > 0 && data != NULL) {
        memcpy(buffer, data, len);
    }
}

// 2. Heap Buffer Overflow
__attribute__((visibility("default")))
void vuln_heap_overflow(const char* data, size_t len) {
    char* buf = (char*)malloc(16);
    if (!buf) return;
    
    // VULNERABILITY: Writing more than 16 bytes to the heap
    if (data != NULL) {
        memcpy(buf, data, len);
    }
    free(buf);
}

// 3. Use-After-Free (UAF)
__attribute__((visibility("default")))
void vuln_use_after_free(const char* data, size_t len) {
    if (len < 2 || data == NULL) return;
    
    char* buf = (char*)malloc(32);
    if (!buf) return;
    
    if (data[0] == 'X') {
        free(buf); // Free early
    }
    
    // VULNERABILITY: Use after free if data[0] == 'X'
    if (data[1] == 'Y') {
        buf[0] = 'Z'; // Write to freed memory
    }
    
    if (data[0] != 'X') {
        free(buf);
    }
}

// 4. Divide by Zero
__attribute__((visibility("default")))
void vuln_divide_by_zero(const char* data, size_t len) {
    if (len < 1 || data == NULL) return;
    
    int divisor = data[0]; 
    // VULNERABILITY: Divide by zero if first byte is 0
    int result = 100 / divisor;
    (void)result;
}
