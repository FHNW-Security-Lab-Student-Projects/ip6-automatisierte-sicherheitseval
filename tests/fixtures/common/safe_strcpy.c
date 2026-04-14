// tests/fixtures/common/safe_strcpy_manual.c
#include <stdio.h>
#include <string.h>

void safe_function(char *user_input) {
    char dest[32];
    
    // SICHER: Explizite Längenprüfung vor dem Kopieren
    if (strlen(user_input) < sizeof(dest)) {
        strcpy(dest, user_input);
        printf("Safe copy: %s\n", dest);
    } else {
        printf("Input too long! Rejected.\n");
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        safe_function(argv[1]);
    }
    return 0;
}