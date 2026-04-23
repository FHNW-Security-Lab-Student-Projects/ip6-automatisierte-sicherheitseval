#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *externer_buffer) {
    gets(externer_buffer); 
}

void nested_function(char *confusing_buffer) {
    char mein_buffer[64];
    printf("Nested function called with confusing_buffer: %s\n", confusing_buffer);
    vulnerable_function(mein_buffer);
}

int main() {
    char confusing_buffer[64];
    nested_function(confusing_buffer);
}