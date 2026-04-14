// tests/fixtures/common/safe_strncpy.c
#include <stdio.h>
#include <string.h>

void safe_function(char *user_input) {
    char dest[32];
    
    // SICHER: Kopiert maximal 31 Bytes, letztes Byte wird explizit auf 0 gesetzt
    strncpy(dest, user_input, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0'; // Immer null-terminieren!
    
    printf("Safe copy: %s\n", dest);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        safe_function(argv[1]);
    }
    return 0;
}