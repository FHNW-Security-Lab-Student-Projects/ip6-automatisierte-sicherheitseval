#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function() {
    char buffer[64];
    
    gets(buffer); 
    
    printf("Function finished normally.\n");
}

int main() {
    vulnerable_function();
    return 0;
}