#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *buffer1 = malloc(64);
    char *buffer2 = malloc(64);
    
    if (buffer1 == NULL || buffer2 == NULL) {
        return 1;
    }

    strcpy(buffer1, "Dies ist ein sicherer Text.");
    strcpy(buffer2, "Auch dieser Block ist sicher.");

    int access_level = 0;

    printf("Program finished safely.\n");
    printf("Access Level: %d\n", access_level);

    free(buffer1);
    free(buffer2);
    
    return 0;
}