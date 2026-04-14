#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_looking_func(char *input) {
    char dest[32];
    
    int len = 0;
    for (int i = 0; i < 1000; i++) {
        if (input[i] == '\0') {
            len = i;
            break;
        }
    }
    
    if (len < 32) {
        strcpy(dest, input);
        printf("Copied.\n");
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable_looking_func(argv[1]);
    }
    return 0;
}