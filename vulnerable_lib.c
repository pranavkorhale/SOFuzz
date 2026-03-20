#include <string.h>

__attribute__((visibility("default")))
void crashme(char *data) {
    char buffer[16];
    strcpy(buffer, data);
}