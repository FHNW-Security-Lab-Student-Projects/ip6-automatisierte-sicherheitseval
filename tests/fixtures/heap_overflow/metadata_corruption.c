#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function(char *user_input) {
    char *buffer = malloc(32);
    
    strcpy(buffer, user_input);
    
    printf("Data copied.\n");
    
    free(buffer);
}

int main(int argc, char **argv) {
    char input[64];
    if (argc > 1) {
        strcpy(input, argv[1]);
        vulnerable_function(input);
    }
    return 0;
}