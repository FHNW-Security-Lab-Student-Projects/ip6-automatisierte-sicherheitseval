#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void process_data(char *dest, char *source) {
    strcpy(dest, source); 
    
    printf("Data copied successfully.\n");
}

int main(int argc, char **argv) {
    char local_dest[32];
    
    if (argc > 2) {
        process_data(local_dest, argv[1]);
    } else {
        printf("Usage: %s <source_data> <ignored_arg>\n", argv[0]);
    }
    
    return 0;
}