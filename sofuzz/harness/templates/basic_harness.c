/*
 * SOFuzz - Basic Harness Template
 * This is a template file - values are replaced during generation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <dlfcn.h>

#define MAX_INPUT_SIZE __MAX_INPUT_SIZE__
#define TIMEOUT_SECONDS __TIMEOUT__
#define SO_PATH "__SO_PATH__"
#define FUNCTION_NAME "__FUNCTION_NAME__"

static sigjmp_buf jump_buffer;
static volatile sig_atomic_t got_signal = 0;

void signal_handler(int sig) {
    got_signal = sig;
    siglongjmp(jump_buffer, 1);
}

void setup_signals(void) {
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGFPE, signal_handler);
    signal(SIGILL, signal_handler);
    signal(SIGBUS, signal_handler);
}

int main(int argc, char* argv[]) {
    setup_signals();
    alarm(TIMEOUT_SECONDS);
    
    uint8_t* buffer = malloc(MAX_INPUT_SIZE);
    if (!buffer) return 1;
    
    size_t size = 0;
    if (argc > 1) {
        FILE* f = fopen(argv[1], "rb");
        if (f) {
            size = fread(buffer, 1, MAX_INPUT_SIZE, f);
            fclose(f);
        }
    } else {
        size = fread(buffer, 1, MAX_INPUT_SIZE, stdin);
    }
    
    if (size == 0) {
        free(buffer);
        return 1;
    }
    
    void* handle = dlopen(SO_PATH, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        free(buffer);
        return 1;
    }
    
    typedef int (*func_t)(const void*, size_t);
    func_t func = (func_t)dlsym(handle, FUNCTION_NAME);
    
    if (!func) {
        fprintf(stderr, "dlsym: %s\n", dlerror());
        dlclose(handle);
        free(buffer);
        return 1;
    }
    
    int result = 0;
    if (sigsetjmp(jump_buffer, 1) == 0) {
        func(buffer, size);
    } else {
        fprintf(stderr, "CRASH: Signal %d\n", got_signal);
        result = 128 + got_signal;
    }
    
    dlclose(handle);
    free(buffer);
    return result;
}