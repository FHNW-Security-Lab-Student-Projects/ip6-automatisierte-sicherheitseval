#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *externer_buffer) {
    gets(externer_buffer); 
}

void nested_function() {
    char mein_buffer[64];
    vulnerable_function(mein_buffer);
}

int main() {
    nested_function();
}