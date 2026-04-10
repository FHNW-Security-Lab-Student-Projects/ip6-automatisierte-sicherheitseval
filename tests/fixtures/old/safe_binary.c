#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void safe_function() {
    char buffer[64];
    
    fgets(buffer, sizeof(buffer), stdin); 
    
    printf("Function finished normally.\n");
}

int main() {
    safe_function();
    return 0;
}