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

void create_user(char *input) {
    struct User *u = malloc(sizeof(struct User));
    strncpy(u->name, input, sizeof(u->name) - 1);
    u->name[sizeof(u->name) - 1] = '\0';
    if (u->is_admin != 0) printf("Admin!\n");
}

int main() {
    char input[64];
    printf("Enter your name: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0; // Remove newline
    create_user(input);
    return 0;
}