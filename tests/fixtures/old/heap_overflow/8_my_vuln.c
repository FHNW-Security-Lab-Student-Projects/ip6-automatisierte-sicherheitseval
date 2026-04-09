#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct User {
    char name[16];
    int is_admin;
};

void create_user(char *input) {
    struct User *u = malloc(sizeof(struct User));
    strcpy(u->name, input); // Overflow! Überschreibt is_admin
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