#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct User {
    char name[16];
    int is_admin; 
    char very_long_buffer[256];
    char another_buffer[128];
    char even_longer_buffer[512];
};

void create_user(char *input, struct User *u) {
    
    strcpy(u->name, input);

    if (u->is_admin != 0) {
        printf("Admin!\n");
    } else {
        printf("Access denied.\n");
    }
}

int main() {
    char input[64];
    struct User u;
    memset(&u, 0, sizeof(struct User));
    printf("Enter your name: ");
    if (fgets(input, sizeof(input), stdin) != NULL) {
        input[strcspn(input, "\n")] = 0; 
        create_user(input, &u);
    }
    return 0;
}