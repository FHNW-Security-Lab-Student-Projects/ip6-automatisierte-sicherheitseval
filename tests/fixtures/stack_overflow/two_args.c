#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void process_data(char *source, char *dest) {
    strcpy(dest, source); 
    
    printf("Data copied successfully.\n");
}

int main(int argc, char **argv) {
    char local_dest[32];
    
    if (argc > 2) {
        process_data(argv[1], local_dest);
    } else {
        printf("Usage: %s <source_data> <ignored_arg>\n", argv[0]);
    }
    
    return 0;
}