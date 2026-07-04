#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *user_buffer;
char *secret_token;

void init_heap() {
    user_buffer = malloc(16);
    secret_token = malloc(16);
    strcpy(secret_token, "SAFE");
}

void read_input() {
    printf("Enter data: ");
    scanf("%s", user_buffer); 
}

void check_security() {
    if (strcmp(secret_token, "SAFE") != 0) {
        printf("VULNERABILITY TRIGGERED: Token modified!\n");
        exit(0); 
    } else {
        printf("System secure.\n");
    }
}

int main() {
    init_heap();
    
    read_input();
    
    check_security();
    
    return 0;
}