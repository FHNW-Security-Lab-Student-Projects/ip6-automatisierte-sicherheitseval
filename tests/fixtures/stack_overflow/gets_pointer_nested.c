#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *externer_buffer) {
    gets(externer_buffer); 
}

void nested_function(char *nested_buffer) {
    vulnerable_function(nested_buffer);
}

int main() {
    char mein_buffer[64];
    nested_function(mein_buffer);
}