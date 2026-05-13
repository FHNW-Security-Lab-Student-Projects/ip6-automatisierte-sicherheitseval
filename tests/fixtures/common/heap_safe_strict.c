#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *buffer = malloc(32);
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    printf("Safe Program: Enter text (max 31 chars):\n");

    if (fgets(buffer, 32, stdin) != NULL) {
        printf("You entered: %s", buffer);
        printf("Access Level: %d (Unchanged)\n", 0);
    }

    free(buffer);
    
    return 0;
}